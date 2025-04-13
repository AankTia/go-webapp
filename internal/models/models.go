package models

import "github.com/jmoiron/sqlx"

type Models struct {
	Users UserModel
	Tokens TokenModel
	Posts PostModel
}

func NewModels(db *sqlx.DB) Models {
	return Models{
		Users: UserModel{DB: db},
		Tokens: TokenModel{DB: db},
		Posts: PostModel{DB: db},
	}
}