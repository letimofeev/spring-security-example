<%@ taglib prefix="security" uri="http://www.springframework.org/security/tags" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
    <title>Title</title>
</head>
<body>
<h3>Information for all employees</h3>

<br><br>

<security:authorize access="hasRole('HR')">
<input type="button" value="Salary"
       onclick="window.location.href='hr-info'">
Only for HR stuff
</security:authorize>

<br><br>

<security:authorize access="hasRole('MANAGER')">
<input type="button" value="Performance"
       onclick="window.location.href='manager-info'">
Only for managers
</security:authorize>

<br><br>

</body>
</html>
