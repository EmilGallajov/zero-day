## Vulnerability Details:
- **Application Name**: Codeastro Hospital Management System (HMS) 
- **Software Link**: [Download Link](https://codeastro.com/hospital-management-system-in-php-with-source-code-adv/)
- **Vendor Homepage**: [Vendor Homepage](https://codeastro.com/)
- **BuG**: Multiple XSS vulnerabilities in different endpoints
- **BUG_Author**: egsec

## About project:
In particular, this Hospital Management System Project in PHP focuses mainly on managing medical-related records within the hospital. To be more precise, the system helps to keep track of medical reports. Also, the system displays all the available employees and patients. In addition, the system allows adding up inventories, and pharmacy records too(codeastro.com). Evidently, this project contains an admin panel with an employee/doctor panel. In an overview of this web application, a doctor can simply log into the system using his/her doctor id and password. He/she can manage patients, pharmacy, and laboratory records. Additionally, the employee/doctor can view and manage inventories too. With it, the system also allows the user to view detailed information and reports of each patient. Besides, the users can update their profiles too.

## Vulnerability Description:
There are several stored xss vulnerabilities in different endpoints. The vulnerability arises from lack of input validation in the application. The web server imputs with POST request with input validation. When the attacker
give an input with xss payload (like simple payload `<script>alert(1)<script>`) instead of normal input, the web application inserts this payload to the database directly after giving sql query. 

## vulnerable endpoints:
The below-mentioned endpoints accepts malicious inputs:

`/backend/admin/his_admin_register_patient.php`

`/backend/admin/his_admin_add_lab_equipment.php`

`/backend/admin/his_admin_add_vendor.php`

`/backend/doc/his_doc_register_patient.php`

## vulnerable code sections:
------------------------------------------------------------------------
for `/his_admin_register_patient.php`:
```php
<?php
	session_start();
	include('assets/inc/config.php');
		if(isset($_POST['add_patient']))
		{  // vulnerable code sections lack of input validation in $_POST requests
			$pat_fname=$_POST['pat_fname'];
			$pat_lname=$_POST['pat_lname'];
			$pat_number=$_POST['pat_number'];
            $pat_phone=$_POST['pat_phone'];
            $pat_type=$_POST['pat_type'];
            $pat_addr=$_POST['pat_addr'];
            $pat_age = $_POST['pat_age'];
            $pat_dob = $_POST['pat_dob'];
            $pat_ailment = $_POST['pat_ailment'];
            //sql to insert captured values
			$query="insert into his_patients (pat_fname, pat_ailment, pat_lname, pat_age, pat_dob, pat_number, pat_phone, pat_type, pat_addr) values(?,?,?,?,?,?,?,?,?)";
			$stmt = $mysqli->prepare($query);
			$rc=$stmt->bind_param('sssssssss', $pat_fname, $pat_ailment, $pat_lname, $pat_age, $pat_dob, $pat_number, $pat_phone, $pat_type, $pat_addr);
			$stmt->execute();
			/*
			*Use Sweet Alerts Instead Of This Fucked Up Javascript Alerts
			*echo"<script>alert('Successfully Created Account Proceed To Log In ');</script>";
			*/ 
			//declare a varible which will be passed to alert function
			if($stmt)
			{
				$success = "Patient Details Added";
			}
			else {
				$err = "Please Try Again Or Try Later";
			}
			
			
		}
?>
```
-----------------------------------------------
for `/his_admin_add_lab_equipment.php`:

```php
<?php
	session_start();
	include('assets/inc/config.php');
        if(isset($_POST['add_equipments'])){ // vulnerable code sections lack of input validation in $_POST requests
		    $eqp_code = $_POST['eqp_code'];
			  $eqp_name = $_POST['eqp_name'];
            $eqp_vendor = $_POST['eqp_vendor'];
            $eqp_desc = $_POST['eqp_desc'];
            $eqp_dept = $_POST['eqp_dept'];
            $eqp_status = $_POST['eqp_status'];
            $eqp_qty = $_POST['eqp_qty'];
                
            //sql to insert captured values
			$query="INSERT INTO his_equipments (eqp_code, eqp_name, eqp_vendor, eqp_desc, eqp_dept, eqp_status, eqp_qty) VALUES (?,?,?,?,?,?,?)";
			$stmt = $mysqli->prepare($query);
			$rc=$stmt->bind_param('sssssss', $eqp_code, $eqp_name, $eqp_vendor, $eqp_desc, $eqp_dept, $eqp_status, $eqp_qty);
			$stmt->execute();
			/*
			*Use Sweet Alerts Instead Of This Fucked Up Javascript Alerts
			*echo"<script>alert('Successfully Created Account Proceed To Log In ');</script>";
			*/ 
			//declare a varible which will be passed to alert function
			if($stmt)
			{
				$success = "Laboratory Equipment Added";
			}
			else {
				$err = "Please Try Again Or Try Later";
			}
			
			
		}
?>
```
-----------------------------------------------
for `/his_admin_add_vendor.php`:

```php
<?php
	session_start();
	include('assets/inc/config.php');
		if(isset($_POST['add_vendor']))
		{// vulnerable code sections lack of input validation in $_POST requests
			$v_name=$_POST['v_name'];
			$v_adr=$_POST['v_adr'];
			$v_number=$_POST['v_number'];
            $v_email=$_POST['v_email'];
            $v_phone = $_POST['v_phone'];
            $v_desc = $_POST['v_desc'];
            //$doc_pwd=sha1(md5($_POST['doc_pwd']));
            
            //sql to insert captured values
			$query="INSERT INTO his_vendor (v_name, v_adr, v_number, v_email, v_phone, v_desc) values(?,?,?,?,?,?)";
			$stmt = $mysqli->prepare($query);
			$rc=$stmt->bind_param('ssssss', $v_name, $v_adr, $v_number, $v_email, $v_phone, $v_desc);
			$stmt->execute();
			/*
			*Use Sweet Alerts Instead Of This Fucked Up Javascript Alerts
			*echo"<script>alert('Successfully Created Account Proceed To Log In ');</script>";
			*/ 
			//declare a varible which will be passed to alert function
			if($stmt)
			{
				$success = "Vendor Details Added";
			}
			else {
				$err = "Please Try Again Or Try Later";
			}
			
			
		}
?>
```
-----------------------------------------------
for `/his_doc_register_patient.php`:

```php
<?php
	session_start();
	include('assets/inc/config.php');
		if(isset($_POST['add_patient']))
		{// vulnerable code sections lack of input validation in $_POST requests
			$pat_fname=$_POST['pat_fname'];
			$pat_lname=$_POST['pat_lname'];
			$pat_number=$_POST['pat_number'];
            $pat_phone=$_POST['pat_phone'];
            $pat_type=$_POST['pat_type'];
            $pat_addr=$_POST['pat_addr'];
            $pat_age = $_POST['pat_age'];
            $pat_dob = $_POST['pat_dob'];
            $pat_ailment = $_POST['pat_ailment'];
            //sql to insert captured values
			$query="insert into his_patients (pat_fname, pat_ailment, pat_lname, pat_age, pat_dob, pat_number, pat_phone, pat_type, pat_addr) values(?,?,?,?,?,?,?,?,?)";
			$stmt = $mysqli->prepare($query);
			$rc=$stmt->bind_param('sssssssss', $pat_fname, $pat_ailment, $pat_lname, $pat_age, $pat_dob, $pat_number, $pat_phone, $pat_type, $pat_addr);
			$stmt->execute();
			/*
			*Use Sweet Alerts Instead Of This Fucked Up Javascript Alerts
			*echo"<script>alert('Successfully Created Account Proceed To Log In ');</script>";
			*/ 
			//declare a varible which will be passed to alert function
			if($stmt)
			{
				$success = "Patient Details Added";
			}
			else {
				$err = "Please Try Again Or Try Later";
			}
			
			
		}
?>
```

## Proof of Concept (PoC):
PoC video is uploaded to the youtube:
[click to the link](https://www.youtube.com/watch?v=UsScmd8Xzuw)

## Mitigation:
- Escape Data Before Inserting into the Database.
- Restrict Allowed Input.
  Use a whitelist approach:
  For example, limit the characters allowed in fields.
  `$name = preg_replace("/[^a-zA-Z\s]/", "", $_POST['name']);`
  By restricting the input to letters (a-zA-Z) and spaces (\s), it prevents special characters like <, >, ', ", and & from being included in the input. These characters are often used in crafting XSS payloads (e.g., <script>alert('XSS')</script>).
  This approach is effective for specific fields that only expect alphabetic names, such as a first_name or last_name.
- Use htmlspecialchars() for Output Escaping.
- Additionally, use trim() in order to remove whitespaces.
