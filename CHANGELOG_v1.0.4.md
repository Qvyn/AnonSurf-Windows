# AnonSurf Safe v1.0.4

- Replaced the Tkinter interface with a modern PySide6/Qt 6 interface.
- Added a persistent Windows notification-area icon.
- Closing or minimizing the window now hides it to the notification area.
- Added tray actions for Open, Enable/Disable, Refresh, New identity, and Exit.
- Added safe tray exit handling that restores the Windows proxy before quitting.
- Added live tray status, active/inactive icon state, and one-time tray guidance.
- Kept the v1.0.3 idle-tunnel fix and automatic recovery watchdog.
- Updated the requirements and standalone build script for PySide6.
