package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"strconv"
	"time"

	_ "modernc.org/sqlite"
)

const dbFile = "totally_not_my_privateKeys.db"

func initDB() (*sql.DB, error) {
	db, err := sql.Open("sqlite", dbFile)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS keys (
		kid INTEGER PRIMARY KEY AUTOINCREMENT,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	)`)
	if err != nil {
		db.Close()
		return nil, err
	}

	return db, nil
}

func saveNewKey(db *sql.DB, expiration time.Time) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	keyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	})

	_, err = db.Exec(
		"INSERT INTO keys (key, exp) VALUES (?, ?)",
		pemBytes,
		expiration.Unix(),
	)
	return err
}

func loadKey(kid int64, keyBytes []byte, exp int64) (Key, error) {
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return Key{}, fmt.Errorf("invalid PEM data")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return Key{}, err
	}

	return Key{
		PrivateKey: privateKey,
		Kid:        strconv.FormatInt(kid, 10),
		ExpiresAt:  time.Unix(exp, 0),
	}, nil
}

func getKey(db *sql.DB, expired bool) (Key, error) {
	query := "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp DESC LIMIT 1"
	if expired {
		query = "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1"
	}

	var kid int64
	var keyBytes []byte
	var exp int64

	err := db.QueryRow(query, time.Now().Unix()).Scan(
		&kid, &keyBytes, &exp,
	)
	if err != nil {
		return Key{}, err
	}

	return loadKey(kid, keyBytes, exp)
}

func getValidKeys(db *sql.DB) ([]Key, error) {
	rows, err := db.Query(
		"SELECT kid, key, exp FROM keys WHERE exp > ?",
		time.Now().Unix(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []Key

	for rows.Next() {
		var kid int64
		var keyBytes []byte
		var exp int64

		if err := rows.Scan(&kid, &keyBytes, &exp); err != nil {
			return nil, err
		}

		key, err := loadKey(kid, keyBytes, exp)
		if err != nil {
			return nil, err
		}

		keys = append(keys, key)
	}

	return keys, rows.Err()
}
