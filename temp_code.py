import sqlite3

def login(username, password):
    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()

    # Vulnerable query, susceptible to SQL injection
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    
    cursor.execute(query)
    user = cursor.fetchone()

    connection.close()

    return user

if __name__ == "__main__":
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    
    user = login(username, password)
    
    if user:
        print("Login successful!")
    else:
        print("Invalid username or password.")
