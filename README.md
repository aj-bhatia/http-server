# CSE 130: Assignment 2
## Files:
- httpserver.c:
    Implementation for the httpserver file. Code is entirely contained within httpserver.c, but many functions are written as individual pieces to create the full implementation.

- Makefile:
    File used to make executable binary versions of httpserver.c. Uses the gcc compiler and clang flags to compile c files.

## How to make httpserver.c:
In order to run the httpserver.c file, one must first compile and make the file to create an executable of the file. In order to do that, we can use Ubuntu 20.04, where we can run make commands. Once in the terminal, navigate to the proper directory and run `make` to make an executable of the httpserver.c file. Afterwards, there should be an executable file simply called `httpserver`, which can be run to execute the program.

## How to run httpserver.c:
Once the httpserver executable file has been created, we can run the file through the prefix `./`. Prepending this to the httpserver executable will execute the file, so, the command `./httpserver` can be used to do so. Despite being able to run the file, in order to properly execute the code as intended, `./httpserver` requires one argument. The required argument is a port at which to open the server. \
The command should be run in the format `./httpserver <port>`\

## Design Decisions:
- With a project with such a scale as this, it was difficult for me to come up with an effective modularity style. Initially, I thought to use a layering technique in order to create different sections of the code that only interact with certain other parts of my code. This partially worked, but did not seperate the functions as well as I wanted them to. So instead, I later opted to utilize a hierarchy that created seperation between modules in order to run the system. This system became very effective as it allowed for a decrease in complexity of my system, while still retaining functionality with small modifications of the functions. Because I swapped styles part way through the process, I utilized both Top-Down modularity at the beginning, but also took into account Bottom-Up modularity to round out the system. The modules that I utilized were a Request Module, a Processing Module, and Response Module. Each indivually had many more parts to them, but by seperating the main aspects of the code into these three large modules, I was able to seperate their processes and depend on fewer function calls/returns from functions between modules.
- While I heavily took into account modularity and how to seperate functions to avoid unnecessary complexity, I did decide to use global variables as an easy and consistent way to create response messages during the execution of other functions. Because of how careful I was when using functions that could change the values of the global variables, this worked, but it did result in less modularity between my functions and modules. The other ways that I thought about creating this interaction between modules passing values to the response module could have worked, but it would have required a different set up of functionality in my functions, which I did not want to change.
- Something that I struggled to effectively decide on was how I wanted to pass return values for errors between functions and modules. This was something that tied in heavily with my decision to use global variables in order to keep track of the responses, as it was difficult for me to find a way to effectively pass error values all the way back to the intial large modules, and then eventually send the response that was appropriate with the error. So instead of going that route, I decided it would be best for me to instead set it up so that the functions that return errors set the global variables to the proper error, and then return an error. Thus, in every function of each module, anytime a function is called, I do a simple check to see if the called function returned an error, if so, I would also return an error from that function. This chains all the way down to the main module, where the response is then called, and having the global variables already set means that the response is ready. So, this process of checking each call for an error led to a very easy and simple way to call other functions and modules within larger components.
- One of the last issues I had was replicating the behavior of the reference file on specific inputs. This issue mainly arose when there was a case of an infinite loop due to some input. Because I was unsure what in the reference implementation caused this issue, I decided to tackle this problem in a roundabout way, using infinite while loops wherever this error should've occurred. This was not an amazing decision in terms of code quality, but I felt it needed to be done in order to be more similar to the reference implementation.
- The last design decision I made was in the way I validated the requests. In many places, I ended up doing more work than required while validating so that when the request was processed, there would be 0 issues. This meant that I initially would do things like find "Content-Length" in the request before required, and then find it again later when processing the request, or opening the file for writing/reading before needing to, just to ensure I would be able to while reading/writing from/to it. This resulted in some extra work being done by my program, but it resulted in better modularity, because while processing the requests, there would be little to no issues that could arrise, becaues they would have all been checked prior to being run.
- While adding the audit log, I also had to make some decisions on how the ouput should have worked. In order to keep in similarity with my previous code and structure, I added more global variables to match the needs of storing the uri and method of the requests, so they could be properly logged out. This decreased modularity slightly, but allowed me to easily integrate an audit log to the server, and continue full functionality.