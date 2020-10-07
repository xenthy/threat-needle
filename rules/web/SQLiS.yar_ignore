rule SQLi: mal 								// tag: mal
{
	meta: 								// meta: additional information
									// won't affect code
	    author = "Matthew Jang"
	    maltype = "SQL Injection for MySQL, Oracle, SQL Server, etc."
	    reference = "https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/#SyntaxBasicAttacks"
	    description = "YARA rule to detect the most common SQL injection commands/strings"

	strings:

	    $char1 = "1=1"						// 1=1 is always true
	    $char2 = "--" 						// line comments
	    $char3 = "#"
	    $str1 = "CONCAT" nocase    				// for MySQL
	    $str2 = "CHAR" nocase
	    $str3 = "Hex" nocase
	    $str4 = "admin' --"					// bypassing login screen
	    $str5 = "admin' #"
	    $str6 = "admin' /*"                                                                       
	    $str7 = "anotheruser" nocase
	    $str8 = "doesnt matter" nocase
	    $str9 = "MD5" nocase
	    $str10 = "HAVING" nocase 
	    $str11 = "ORDER BY" nocase
	    $str12 = "CAST" nocase
	    $str13 = "CONVERT" nocase
	    $str14 = "insert" nocase
	    $str15 = "@@version"
	    $str16 = "bcp" nocase
	    $str17 = "VERSION" nocase
	    $str18 = "WHERE" nocase
	    $str19 = "LIMIT" nocase
	    $str20 = "EXEC" nocase 
	    $str21 = "';shutdown --"
	    $str22 = "WAITFOR DELAY" nocase
	    $str23 = "NOT EXIST" nocase
	    $str24 = "NOT IN" nocase
	    $str25 = "BENCHMARK" nocase
	    $str26 = "pg_sleep"
	    $str27 = "sleep" 		 			// for MySQL
	    $str28 = "--sp_password" nocase
	    $str29 = "SHA1" nocase
	    $str30 = "PASSWORD" nocase
	    $str31 = "ENCODE" nocase
	    $str32 = "COMPRESS" nocase
	    $str33 = "SCHEME" nocase
	    $str34 = "ROW_COUNT" nocase
	    $str35 = "DROP members--" nocase
	    $str36 = "ASCII" nocase
	    $str37 = "UNION" nocase
	    $str38 = "UNION SELECT" nocase
	    $str39 = "INFORMATION" nocase
	    $str40 = "SCHEMA" nocase
	    $str41 = "INFORMATION_SCHEMA" nocase 

	condition: 

	    any of them

}



 /*

 Ruby Script to Detect SQL Injection
 ###########################
 ###  Union based  ###
 ###########################
        "Find Vulnerable Column Count by Union based"=>/(ORDER.BY.\d+(\-\-|\#))|(?!.*(CONCAT.*))(UNION.ALL.SELECT.(NULL|\d+).*(\-\-|\#))/i,
        "Find DBMS Version Infomation by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(VERSION\(|@@VERSION)/i,
        "Find Hostname by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(@@HOSTNAME)/i,
        "Find DB Administrator by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(super_priv.*FROM.*mysql.user)/i,
        "Find Privileges Count by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*COUNT.*(privilege_type|\*).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES/i,
        "Find Privileges Name by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(privilege_type|\*).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES/i,
        "Find User Count by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*COUNT.*(grantee).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES/i,
        "Find User Name by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(grantee).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES/i,
        "Find Database Count by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(COUNT.*(schema_name)).*FROM.*INFORMATION_SCHEMA.SCHEMATA/i,
        "Find Database Name by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(schema_name).*FROM.*INFORMATION_SCHEMA.SCHEMATA/i,
        "Find Current User by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(CURRENT_USER\()/i,
        "Find Current Database by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(DATABASE\()/i,
        "Find Table Count by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(COUNT.*(table_name|\*)).*FROM.*INFORMATION_SCHEMA.TABLES/i,
        "Find Table Name by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(table_name|\*).*FROM.*INFORMATION_SCHEMA.TABLES/i,
        "Find Column Count by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(COUNT.*(column_name|\*)).*FROM.*INFORMATION_SCHEMA.COLUMNS/i,
        "Find Column Name & Type by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(column_name|column_type).*FROM.*INFORMATION_SCHEMA.COLUMNS/i,
        "Find Column Data Count by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(CAST.*(COUNT\((\*|\w+)).*FROM.*\w+\.\w+)/i,
        "Find Column Data by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(SELECT.*(CAST.*(\w+).*FROM.*\w+\.\w+))/i,
        "Brute Force Table Name by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(SELECT.\d+.FROM.*\w+)/i,
        "Brute Force Column Name by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(SELECT.(\`|)(\[|\]|)(\w+|(\w+\-)*\w+)(\[|\]|)(\`|).FROM.*\w+)/i,
        "Find Vulnerable Column Location by Union based"=>/(?=.*(CONCAT.*))(UNION.ALL.SELECT.(NULL|\w+).*(\-\-|\#))/i,

###########################
###  Error based  ###
###########################
        "Find Vulnerable Type by Error based"=>/(0x\w+.*((SELECT.*(ELT.*(\d+\=\d+)))|(SELECT.*(CASE.*WHEN.*(\d+\=(\s|\d+))))).*0x\w+)/i,
        "Find DBMS Version Infomation by Error based"=>/(0x\w+.*(MID.*(VERSION\(|@@VERSION)).*0x\w+)/i,
        "Find Hostname by Error based"=>/(0x\w+.*(MID.*(@@HOSTNAME)).*0x\w+)/i,
        "Find DB Administrator by Error based"=>/(0x\w+.*(SELECT.*super_priv.*FROM.*mysql.user).*0x\w+)/i,
        "Find User Count by Error based"=>/(0x\w+.*(SELECT.*(COUNT.*(grantee).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES)).*0x\w+)/i,
        "Find User Name by Error based"=>/(0x\w+.*(MID.*((grantee)).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES).*0x\w+)/i,
        "Find Privileges Count by Error based"=>/(0x\w+.*(SELECT.*(COUNT.*(privilege_type|\*).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES)).*0x\w+)/i,
        "Find Privileges Name by Error based"=>/(0x\w+.*(MID.*(privilege_type)).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES.*0x\w+)/i,
        "Find Database Count by Error based"=>/(0x\w+.*(SELECT.*(COUNT\((\w+|\*)).*FROM.*INFORMATION_SCHEMA.SCHEMATA).*0x\w+)/i,
        "Find Database Name by Error based"=>/(0x\w+.*(SELECT.*(\w+|\*).*FROM.*INFORMATION_SCHEMA.SCHEMATA).*0x\w+)/i,
        "Find Current User by Error based"=>/(0x\w+.*(MID.*(CURRENT_USER\()).*0x\w+)/i,
        "Find Current Database by Error based"=>/(0x\w+.*(MID.*(DATABASE\()).*0x\w+)/i,
        "Find Table Count by Error based"=>/(0x\w+.*(SELECT.*(COUNT\((\w+|\*)).*FROM.*INFORMATION_SCHEMA.TABLES.*0x\w+))/i,
        "Find Table Name by Error based"=>/(0x\w+.*(SELECT.*(\w+|\*).*FROM.*INFORMATION_SCHEMA.TABLES.*0x\w+))/i,
        "Find Column Count by Error based"=>/(0x\w+.*(SELECT.*(COUNT\((\w+|\*)).*FROM.*INFORMATION_SCHEMA.COLUMNS.*0x\w+))/i,
        "Find Column Type by Error based"=>/(0x\w+.*(SELECT.*MID.*(column_type)).*FROM.*INFORMATION_SCHEMA.COLUMNS.*0x\w+)/i,
        "Find Column Name by Error based"=>/(0x\w+.*(SELECT.*MID.*(column_name)).*FROM.*INFORMATION_SCHEMA.COLUMNS.*0x\w+)/i,
        "Find Column Data Count by Error based"=>/(0x\w+.*(SELECT.*(COUNT\((\*|\w+).*FROM.*\w+\.\w+).*0x\w+))/i,
        "Find Column Data by Error based"=>/(0x\w+.*(SELECT.*MID.*(CAST.*(\w+).*FROM.*\w+\.\w+).*\w+))/i,
        "Brute Force Table Name by Error based"=>/(0x\w+.*EXISTS.(SELECT.\d+.FROM.*\w+).*0x\w+)/i,
        "Brute Force Column Name by Error based"=>/(0x\w+.*EXISTS.(SELECT.(\`|)(\[|\]|)(\w+|(\w+\-)*\w+)(\[|\]|)(\`|).FROM.*\w+).*0x\w+)/i,
  	    "Check String Repeat by Error based"=>/(0x\w+.*(SELECT.*REPEAT.*0x\w+))/i,

###########################
###  Time blind based ###
###########################
        "Find DBMS Version Infomation by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*ORD.*(MID.*(VERSION\(|@@VERSION\()))/i,
        "Find Hostname by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*ORD.*(MID.*(@@HOSTNAME)))/i,
        "Find DB Administrator by Time based"=>/(SELECT.*super_priv.*FROM.*mysql.user)/i,
        "Find User Count by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*ORD.*(MID.*(SELECT.*(COUNT.*(grantee).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES))))/i,
        "Find User Name by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*ORD.*(MID.*(SELECT.*((grantee)).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES)))/i,
        "Find Privileges Count by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*ORD.*(MID.*(SELECT.*(COUNT.*(privilege_type).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES))))/i,
        "Find Privileges Name by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*ORD.*(MID.*(SELECT.*((privilege_type)).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES)))/i,
        "Find Database Count by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*ORD.*(MID.*(SELECT.*(COUNT\(.*(\w+|\*).*FROM.*INFORMATION_SCHEMA.SCHEMATA))))/i,
        "Find Database Name by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*ORD.*(MID.*(SELECT.*(\w+|\*).*FROM.*INFORMATION_SCHEMA.SCHEMATA)))/i,
        "Find Current User by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*ORD.*(MID.*(CURRENT_USER\()))/i,
        "Find Current Database by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*ORD.*(MID.*(DATABASE\()))/i,
        "Find Table Count by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*ORD.*(MID.*(SELECT.*(COUNT\((\w+|\*)).*FROM.*INFORMATION_SCHEMA.TABLES)))/i,
        "Find Table Name by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*ORD.*(MID.*(SELECT.*(\w+|\*).*FROM.*INFORMATION_SCHEMA.TABLES)))/i,
        "Find Column Count by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*ORD.*(MID.*(SELECT.*(COUNT\((\w+|\*)).*FROM.*INFORMATION_SCHEMA.COLUMNS)))/i,
        "Find Column Type by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*ORD.*(MID.*(SELECT.*(column_type).*FROM.*INFORMATION_SCHEMA.COLUMNS)))/i,
        "Find Column Name by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*ORD.*(MID.*(SELECT.*(column_name).*FROM.*INFORMATION_SCHEMA.COLUMNS)))/i,
	    "Find Column Data Count by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*ORD.*(MID.*(SELECT.*(COUNT\((\*|\w).*FROM.*\w+\.\w+))))/i,
	    "Find Column Data by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*ORD.*(MID.*(SELECT.*\w+.*FROM.*\w+\.\w+)))/i,
        "Brute Force Table Name by Time based"=>/(?=.*(SLEEP\(\d|BENCHMARK\(\d)).*(EXISTS.(SELECT.\d+.FROM.*\w+))/i,
        "Brute Force Column Name by Time based"=>/(?=.*(SLEEP\(\d|BENCHMARK\(\d)).*(EXISTS.(SELECT.(\`|)(\[|\]|)(\w+|(\w+\-)*\w+)(\[|\]|)(\`|).FROM.*\w+))/i,
        "Find Vulnerable Type by Time based"=>/(SLEEP\(\d|BENCHMARK\(\d)/i,

###############################
###  Boolean blind based ###
###############################
	"Find Vulnerable Type by Boolean based"=>/(\d+.(\=|\s|\>)\d+)|(\d+\=.*\d+)/i,
	"Find DBMS Version Infomation by Boolean based"=>/(ORD.*(MID.*(VERSION\(|@@VERSION)))/i,
	"Find Hostname by Boolean based"=>/(ORD.*(MID.*(@@HOSTNAME)))/i,
	"Find DB Administrator by Boolean based"=>/(SELECT.*super_priv.*FROM.*mysql.user)/i,
	"Find User Count by Boolean based"=>/(ORD.*(MID.*(SELECT.*(COUNT.*(grantee).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES))))/i,
	"Find User Name by Boolean based"=>/(ORD.*(MID.*(SELECT.*((grantee)).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES)))/i,
	"Find Privileges Count by Boolean based"=>/(ORD.*(MID.*(SELECT.*(COUNT.*(privilege_type).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES))))/i,
	"Find Privileges Name by Boolean based"=>/(ORD.*(MID.*(SELECT.*((privilege_type)).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES)))/i,
	"Find Database Count by Boolean based"=>/(ORD.*(MID.*(SELECT.*(COUNT\(.*(\w+|\*).*FROM.*INFORMATION_SCHEMA.SCHEMATA))))/i,
	"Find Database Name by Boolean based"=>/(ORD.*(MID.*(SELECT.*(\w+|\*).*FROM.*INFORMATION_SCHEMA.SCHEMATA)))/i,
	"Find Current User by Boolean based"=>/(ORD.*(MID.*(CURRENT_USER\()))/i,
	"Find Current Database by Boolean based"=>/(ORD.*(MID.*(DATABASE\()))/i,
	"Find Table Count by Boolean based"=>/(ORD.*(MID.*(SELECT.*(COUNT\((\w+|\*)).*FROM.*INFORMATION_SCHEMA.TABLES)))/i,
	"Find Table Name by Boolean based"=>/(ORD.*(MID.*(SELECT.*(\w+|\*).*FROM.*INFORMATION_SCHEMA.TABLES)))/i,
	"Find Column Count by Boolean based"=>/(ORD.*(MID.*(SELECT.*(COUNT\((\w+|\*)).*FROM.*INFORMATION_SCHEMA.COLUMNS)))/i,
	"Find Column Type by Boolean based"=>/(ORD.*(MID.*(SELECT.*(column_type).*FROM.*INFORMATION_SCHEMA.COLUMNS)))/i,
	"Find Column Name by Boolean based"=>/(ORD.*(MID.*(SELECT.*(column_name).*FROM.*INFORMATION_SCHEMA.COLUMNS)))/i,
	"Find Column Data Count by Boolean based"=>/(ORD.*(MID.*(SELECT.*(COUNT\((\*|\w).*FROM.*\w+\.\w+))))/i,
    "Find Column Data by Boolean based"=>/(ORD.*(MID.*(SELECT.*\w+.*FROM.*\w+\.\w+)))/i,
	"Brute Force Table Name by Boolean based"=>/(EXISTS.(SELECT.\d+.FROM.*\w+))/i,
	"Brute Force Column Name by Boolean based"=>/(EXISTS.(SELECT.(\`|)(\[|\]|)(\w+|(\w+\-)*\w+)(\[|\]|)(\`|).FROM.*\w+))/i,

	}
*/

// Ideas:
// Multiple rules for each case (i.e. One for Blind, one for Union...)
// Can YARA print the line of log file that it detected?
// Real-time - possible with script so that when log comes up, it is automatically sent to YARA
