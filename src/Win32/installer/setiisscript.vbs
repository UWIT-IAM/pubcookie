dim objRoot
dim objDirectory

On Error Resume Next

Set Container = GetObject("IIS://Localhost/W3SVC")

If Err = 0 Then
    For Each Child in Container
      If Child.Class = "IIsWebServer" Then

		Set objRoot = Child.GetObject("IISWebVirtualDir", "Root")
		Set objDirectory = objRoot.GetObject("IISWebDirectory", "PBC_RELAY")
		If Err Then
			Err = 0
			Set objDirectory = objRoot.Create("IISWebDirectory", "PBC_RELAY")
		End If
		If Err Then
			msgbox("Could not open relay directory.  Script permissions not set.")
			Exit For
		End If
		
		objDirectory.AccessScript = "True"
		objDirectory.AccessRead = "True"
		objDirectory.AccessExecute = "True"
		objDirectory.SetInfo 

          If Err = 0 Then
              msgbox("Added Pubcookie relay to " & Child.ServerComment & ".")
		  Else
	          msgbox("Problem encountered adding Pubcookie relay to " & Child.ServerComment & ", error: " & Err & ".")
		  End If
          Exit For
      End If
    Next
Else
    msgbox("Could not open metabase, error: " & Err & ". Pubcookie relay has not been added to any web server instances.")
End If

