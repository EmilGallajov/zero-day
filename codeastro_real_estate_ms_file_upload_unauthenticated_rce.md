## Vulnerability Details:
- **Application Name**: Codeastro Real Estate Management System 
- **Software Link**: [Download Link](https://codeastro.com)
- **Vendor Homepage**: [Vendor Homepage](https://github.com/anirbandutta9/NEWS-BUZZ)
- **BuG**: Arbitrary Unauthenticated File Upload Leading to Remote Code Execution (RCE)
- **BUG_Author**: egsec

## About project:
In particular, this Real Estate Management System Project in PHP focuses mainly on publishing and viewing properties. To be more precise, the system helps to keep a number of sales and rental properties.

## Vulnerability Description:
- An arbitrary unauthenticated file upload vulnerability was discovered in the `/register.php` endpoint of the application. This endpoint allows users to upload profile pictures as part of the registration process, but lacks proper file validation and authentication checks. Attackers can exploit this flaw by uploading a malicious file (e.g., a PHP reverse shell) as the user picture, which the server subsequently processes. This ultimately allows attackers to execute arbitrary code on the server, leading to remote code execution (RCE).

## Vulnerable Code Section:
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
- go to the user register location => `http://localhost/RealEstate-PHP/register.php`
  
  ![image](https://github.com/user-attachments/assets/67569737-996d-4fdc-a4e4-846e74b3b6c6)

- upload the malicious file (shell.php) 
