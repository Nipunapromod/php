<?php
// Database connection settings for PostgreSQL
$servername = "c8lj070d5ubs83.cluster-czrs8kj4isg7.us-east-1.rds.amazonaws.com";
$username = "u1g0tnintcbbsa";
$password = "p811d5282cee4da7f3f019d365a9942028434be3f20506b9f28647edce95fd57e";
$dbname = "dc20ejudbt6r1v";

// Function to connect to PostgreSQL database
function connectDB() {
    global $servername, $username, $password, $dbname;

    try {
        // Create connection using PostgreSQL PDO
        $conn = new PDO("pgsql:host=$servername;dbname=$dbname", $username, $password);
        // Set PDO error mode to exception for error handling
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        return $conn;
    } catch(PDOException $e) {
        die("Connection failed: " . $e->getMessage());
    }
}

// Function to register a user
function registerUser($email, $username, $password) {
    try {
        $conn = connectDB();
        // Hash the password before storing
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
        
        // Prepare the SQL query to insert user data
        $stmt = $conn->prepare("INSERT INTO users (email, username, password) VALUES (:email, :username, :password)");
        $stmt->bindParam(':email', $email);
        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':password', $hashedPassword);
        
        // Execute the query and return true on success
        return $stmt->execute();
    } catch(PDOException $e) {
        return false;
    }
}

// Function to login a user
function loginUser($email, $password) {
    try {
        $conn = connectDB();
        // Prepare the SQL query to retrieve user data based on email
        $stmt = $conn->prepare("SELECT * FROM users WHERE email = :email");
        $stmt->bindParam(':email', $email);
        $stmt->execute();
        
        // Fetch the user data
        if ($user = $stmt->fetch(PDO::FETCH_ASSOC)) {
            // Verify the password with the hashed password stored in the database
            if (password_verify($password, $user['password'])) {
                return $user;  // Return user data if login is successful
            }
        }
        return false;  // Return false if no matching user or incorrect password
    } catch(PDOException $e) {
        return false;
    }
}
?>
