<?php
// ADL{ve5eeeeeeeeEEEE555ry_si!!iimple_LFI}
$host = 'db';
$dbuser = 'MYSQL_USER';
$dbpassword = 'MYSQL_PASSWORD';
$dbname = 'ctf_users';
$link = mysqli_connect($host, $dbuser, $dbpassword, $dbname);

$loginStatus = NULL;
$username = $_POST['ctf_username'];
$password = $_POST['ctf_password'];

if (isset($username) && isset($password)) {
    error_log('POST: [' . $username . '] [' . $password . ']');
    if ($link) {
        $sql = "SELECT * FROM users WHERE `username` = '$username' AND `password` = '$password';";
        $query = mysqli_query($link, $sql);
        $fetchs = mysqli_fetch_all($query, MYSQLI_ASSOC);
        if (count($fetchs) > 0) {
            foreach ($fetchs as $fetch) {
                if ($fetch["username"] === 'gura' && $fetch["password"] === $password) {
                    $loginStatus = True;
                    break;
                }
                $loginStatus = False;
            }
        } else {
            $loginStatus = False;
        }
    } else {
        $loginStatus = NULL;
    }
} else {
    $loginStatus = NULL;
}
?>
<!doctype html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="author" content="Vongola">
    <title>Gura Dum</title>
    <link href="css/bootstrap.min.css" rel="stylesheet">
    <link href="css/signin.css" rel="stylesheet">
    <link href="css/rainbow.css" rel="stylesheet">
</head>

<body class="text-center" style="display:block;padding: 0;">
    <?php
    if ($loginStatus === True) {
    ?>
        <div class="text-center d-flex justify-content-center flex-column" style="height: 100vh">
            <h1 class="rainbow" style="font-size: 5rem;">Login Success!</h2>
                <p style="font-size: 3em;">
                    <?php echo $_ENV["FLAG"], '<br>'; ?>
                </p>
        </div>
    <?php
    } else {
        if ($loginStatus === False) {
            echo '<div class="alert alert-danger" role="alert">Login Failed! Only admin can use this page to login!</div>';
        }
    ?>
        <div class="text-center d-flex align-items-center" style="height: 90%">
            <form class="form-signin" action="login.php" method="POST">
                <img class="mb-4" src="img/dum.png" width=300></img>
                <label for="inputUsername" class="sr-only">Username</label>
                <input type="text" id="inputUsername" class="form-control" placeholder="Username" name="ctf_username" required autofocus>
                <label for="inputPassword" class="sr-only">Password</label>
                <input type="text" id="inputPassword" class="form-control" placeholder="Password" name="ctf_password" required>
                <div class="checkbox mb-3">
                    <label>
                        <input type="checkbox" value="remember-me"> Remember me
                    </label>
                </div>
                <button class="btn btn-lg btn-primary btn-block" type="submit">Sign in</button>
            </form>
        </div>
    <?php
    }
    ?>
    <script src="js/jquery-slim.min.js"></script>
    <script src="js/popper.min.js"></script>
    <script src="js/bootstrap.min.js"></script>
</body>

</html>