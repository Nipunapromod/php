<?php
session_start();

// Database connection settings (ensure these are kept private)
$host = "c8lj070d5ubs83.cluster-czrs8kj4isg7.us-east-1.rds.amazonaws.com";
$port = "5432";
$dbname = "dc20ejudbt6r1v";
$username = "u1g0tnintcbbsa";
$password = "p811d5282cee4da7f3f019d365a9942028434be3f20506b9f28647edce95fd57e";

// Function to connect to the PostgreSQL database
function connectDB() {
    global $host, $port, $dbname, $username, $password;
    
    try {
        $dsn = "pgsql:host=$host;port=$port;dbname=$dbname";
        $conn = new PDO($dsn, $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        return $conn;
    } catch (PDOException $e) {
        die("Connection failed: " . $e->getMessage());
    }
}

// Function to log in user
function loginUser($email, $password) {
    try {
        $conn = connectDB();
        $stmt = $conn->prepare("SELECT * FROM users WHERE email = :email");
        $stmt->bindParam(':email', $email);
        $stmt->execute();

        if ($user = $stmt->fetch(PDO::FETCH_ASSOC)) {
            if (password_verify($password, $user['password'])) {
                return $user;
            }
        }
        return false;
    } catch(PDOException $e) {
        return false;
    }
}

// Handle login form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Sanitize input
    $email = $_POST['email'] ?? '';
    $password = $_POST['password'] ?? '';

    if (empty($email) || empty($password)) {
        $_SESSION['error'] = "Please fill in all fields";
        header("Location: login.html");
        exit;
    }

    $user = loginUser($email, $password);
    if ($user) {
        // Regenerate session ID for security
        session_regenerate_id(true);
        
        // Store user information in session
        $_SESSION['user'] = $user;
        header("Location: dashboard.php");
        exit;
    } else {
        $_SESSION['error'] = "Invalid email or password";
        header("Location: login.html");
        exit;
    }
}
?>
