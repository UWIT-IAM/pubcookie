# pubcookie relay pages

# redirection to the application
# blank page version

# GET method

<!-- BDB: get -->
<html>
<head>
      <meta http-equiv="Refresh" content="0;URL={APP_URL}">
</head>
</html>
<!-- EDB: get -->
 

# POST method

<!-- BDB: post -->
<html>
<head>
</head>

<body onLoad="document.relay.elements[0].click()">

<form method=post action="{APP_URL}" name=relay>
<input type=submit style="visibility:hidden">

# original args
<!-- BDB: arg -->
<input type=hidden name="{ARGNAME}" value="{ARGVAL}">
<!-- EDB: arg -->

<!-- BDB: area -->
<textarea name="{ARGNAME}" style="visibility:hidden">
{ARGVAL}</textarea>
<!-- EDB: area -->

<noscript>
<p align=center>You do not have Javascript turned on,
please click the button to continue.
<input type=submit value="Continue">
</noscript>


</form>
</html>
<!-- EDB: post -->
 



