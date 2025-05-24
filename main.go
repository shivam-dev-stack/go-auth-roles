package main

import (
	"database/sql"
	"fmt"
	"log"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

type User struct {
	ID       int
	Username string
	Password string
	Role     string
}

func main() {
	// Connect to DB
	db, err := sql.Open("sqlite", "./auth.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Create users table
	createTable := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL,
		role TEXT NOT NULL
	);
	`
	if _, err := db.Exec(createTable); err != nil {
		log.Fatal("Error creating table:", err)
	}

	// CLI Menu
	for {
		var choice int
		fmt.Println("\n1. Register\n2. Login\n3. Exit")
		fmt.Print("Enter choice: ")
		fmt.Scan(&choice)

		switch choice {
		case 1:
			register(db)
		case 2:
			login(db)
		case 3:
			fmt.Println("👋 Exiting...")
			return
		default:
			fmt.Println("❌ Invalid choice.")
		}
	}
}

func register(db *sql.DB) {
	var username, password, role string
	fmt.Print("Choose username: ")
	fmt.Scan(&username)
	fmt.Print("Choose password: ")
	fmt.Scan(&password)
	fmt.Print("Assign role (admin/user): ")
	fmt.Scan(&role)

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Println("❌ Error hashing password:", err)
		return
	}

	// Insert user
	_, err = db.Exec("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", username, hashedPassword, role)
	if err != nil {
		fmt.Println("❌ Registration failed:", err)
		return
	}

	fmt.Println("✅ Registration successful!")
}

func login(db *sql.DB) {
	var username, password string
	fmt.Print("Enter username: ")
	fmt.Scan(&username)
	fmt.Print("Enter password: ")
	fmt.Scan(&password)

	var storedHashedPassword, role string
	err := db.QueryRow("SELECT password, role FROM users WHERE username = ?", username).Scan(&storedHashedPassword, &role)
	if err != nil {
		fmt.Println("❌ Login failed: user not found")
		return
	}

	// Compare hashed password
	if err := bcrypt.CompareHashAndPassword([]byte(storedHashedPassword), []byte(password)); err != nil {
		fmt.Println("❌ Login failed: incorrect password")
		return
	}

	fmt.Printf("🎉 Welcome, %s! Logged in as [%s]\n", username, role)

	if role == "admin" {
		fmt.Println("🔐 Access to admin dashboard!")
	} else {
		fmt.Println("📘 Access to user dashboard!")
	}
}
