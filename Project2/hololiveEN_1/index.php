<!DOCTYPE html>
<html>

<head>
    <meta charset="utf-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>hololiveEN</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.1/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-F3w7mX95PdgyTmZZMECAngseQB83DfGTowi0iMjiWaeVhAn4FJkqJByhZMI3AhiU" crossorigin="anonymous">
</head>

<body>
    <center>
        <form action="index.php" method="get">
            <button class="btn btn-primary" name="page" type="submit" value="gura.html">gura</button>
            <button class="btn btn-primary" name="page" type="submit" value="ame.html">ame</button>
            <button class="btn btn-primary" name="page" type="submit" value="calli.html">calli</button>
            <button class="btn btn-primary" name="page" type="submit" value="ina.html">ina</button>
            <button class="btn btn-primary" name="page" type="submit" value="kiara.html">kiara</button>
        </form>
    </center>
    <div class="text-center d-flex justify-content-center flex-column" style="height: 100vh">
        <p style="font-size: 3em;">
            <?php
            $file = $_GET['page'];
            if (isset($file)) {
                include($file);
            } else {
                include('gura.html');
            }
            ?>
        </p>
    </div>
    <script src="js/jquery-slim.min.js"></script>
    <script src="js/popper.min.js"></script>
    <script src="js/bootstrap.min.js"></script>
</body>

</html>
