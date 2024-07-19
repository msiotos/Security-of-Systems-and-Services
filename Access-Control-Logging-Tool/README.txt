Assignment 2 - msiotos 2016030030 - gangelopoulos 2016030083

-In order for the assignment to work, you need to type:
1. make clean
2. make all
3. make run

You can clean all the files with: make clean

- For the acmonitor to work you must type: ./acmonitor -m OR -i with <file_path> OR -h for help message

- For the acmonitor -i argument to work, you NEED to copy paste the absolute-full path of the file (we used relative filepath) . You can copy this path from the file_logging.log for easier access.

- It is important to note that if the user doesnt have access to the files, it cannot close them as well, and it drops segmentation fault-core dumped as intended.

- When trying to open files after removing access to them we have no fingerprint, as also intended.

- User ID is always 1000, if we wanted we could randomize it with a random function for testing.
