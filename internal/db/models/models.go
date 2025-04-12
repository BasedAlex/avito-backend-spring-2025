package models

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID       uuid.UUID `json:"id" db:"id"`
	Email    string    `json:"email" db:"email"`
	Password string    `json:"password" db:"password"`
	Role     string    `json:"role" db:"role"`
}

type PVZ struct {
	ID       			uuid.UUID 	`json:"id" db:"id"`
	RegistrationDate 	time.Time 	`json:"registration_date" db:"registration_date"`
	City 				string 		`json:"city" db:"city"`
	LastReceptionID 	uuid.UUID 	`json:"last_reception_id" db:"last_reception_id"`
}

type Reception struct {
	ID       			uuid.UUID 	`json:"id" db:"id"`
	ReceivedAt 		time.Time 	`json:"recieved_at" db:"recieved_at"`
	PVZID 				uuid.UUID 	`json:"pvz_id" db:"pvz_id"`
	Status 				string 		`json:"status" db:"status"`
}

type Product struct {
	ID       			uuid.UUID 	`json:"id" db:"id"`
	ReceivedAt 		time.Time 	`json:"received_at" db:"received_at"`
	Type 		string 		`json:"type" db:"type"`
	ReceptionID 		uuid.UUID 	`json:"reception_id" db:"reception_id"`
}