<?php
if ($_SERVER["REQUEST_METHOD"] == "POST"){
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    echo "<h2>Form Submitted</h2>";
    echo "Username: " . htmlspecialchars($username)."<br>";
    echo "Password: " . htmlspecialchars($password);
}else {
    echo "No data submitted.";
}
?>