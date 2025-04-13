package models

import "github.com/jmoiron/sqlx"

func InitDB(dataSourceName string) (*sqlx.DB, error) {
	db, err := sqlx.Open("sqlite3", dataSourceName)
	if err != nil {
		return nil, err
	}

	if err = db.Ping(); err != nil {
		return nil, err
	}

	return db, nil
}
