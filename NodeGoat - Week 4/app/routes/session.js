const UserDAO = require("../data/user-dao").UserDAO;
const AllocationsDAO = require("../data/allocations-dao").AllocationsDAO;
const {
    environmentalScripts
} = require("../../config/config");
const fs = require('fs'); // Import the file system module
const path = require('path'); // Import the path module

/* The SessionHandler must be constructed with a connected db */
function SessionHandler(db) {
    "use strict";

    const userDAO = new UserDAO(db);
    const allocationsDAO = new AllocationsDAO(db);

    // Define log file path. Use an environment variable for flexibility.
    // Default to a path within the container that can be mounted as a volume.
    const logFilePath = process.env.LOG_FILE_PATH || '/app/logs/auth.log';

    // --- REMOVED THE PREVIOUS BLOCK FOR CREATING logDir ---
    // The directory '/app/logs' will be created by the Docker volume mount.
    // fs.createWriteStream will create the 'auth.log' file within it.
    // const logDir = path.dirname(logFilePath);
    // if (!fs.existsSync(logDir)) {
    //     fs.mkdirSync(logDir, { recursive: true });
    // }

    // Create a write stream for authentication logs. 'a' flag appends to the file.
    const logStream = fs.createWriteStream(logFilePath, { flags: 'a' });

    // Optional: Add a log to confirm stream initialization (for debugging)
    console.log(`Log stream initialized for: ${logFilePath}`);


    const prepareUserData = (user, next) => {
        // Generate random allocations
        const stocks = Math.floor((Math.random() * 40) + 1);
        const funds = Math.floor((Math.random() * 40) + 1);
        const bonds = 100 - (stocks + funds);

        allocationsDAO.update(user._id, stocks, funds, bonds, (err) => {
            if (err) return next(err);
        });
    };

    this.isAdminUserMiddleware = (req, res, next) => {
        if (req.session.userId) {
            return userDAO.getUserById(req.session.userId, (err, user) => {
               return user && user.isAdmin ? next() : res.redirect("/login");
            });
        }
        console.log("redirecting to login");
        return res.redirect("/login");

    };

    this.isLoggedInMiddleware = (req, res, next) => {
        if (req.session.userId) {
            return next();
        }
        console.log("redirecting to login");
        return res.redirect("/login");
    };

    this.displayLoginPage = (req, res, next) => {
        return res.render("login", {
            userName: "",
            password: "",
            loginError: "",
            environmentalScripts
        });
    };

    this.handleLoginRequest = (req, res, next) => {
        const {
            userName,
            password
        } = req.body;
        // Capture the client's IP address
        const clientIp = req.ip || req.connection.remoteAddress || 'UNKNOWN_IP';

        userDAO.validateLogin(userName, password, (err, user) => {
            const errorMessage = "Invalid username and/or password";
            const invalidUserNameErrorMessage = "Invalid username";
            const invalidPasswordErrorMessage = "Invalid password";

            if (err) {
                if (err.noSuchUser) {
                    // Log failed login attempt to file for Fail2Ban
                    const logMessage = `${new Date().toISOString()} - Failed login: No such user '${userName}' from IP ${clientIp}\n`;
                    logStream.write(logMessage);
                    console.error(logMessage.trim()); // Also log to stderr for Docker's default logs

                    return res.render("login", {
                        userName: userName,
                        password: "",
                        loginError: invalidUserNameErrorMessage,
                        environmentalScripts
                    });
                } else if (err.invalidPassword) {
                    // Log failed login attempt to file for Fail2Ban
                    const logMessage = `${new Date().toISOString()} - Failed login: Invalid password for user '${userName}' from IP ${clientIp}\n`;
                    logStream.write(logMessage);
                    console.error(logMessage.trim()); // Also log to stderr for Docker's default logs

                    return res.render("login", {
                        userName: userName,
                        password: "",
                        loginError: invalidPasswordErrorMessage,
                        environmentalScripts
                    });
                } else {
                    return next(err);
                }
            }

            // If login is successful, you might want to log that too (optional)
            const successLogMessage = `${new Date().toISOString()} - Successful login for user '${userName}' from IP ${clientIp}\n`;
            logStream.write(successLogMessage);
            console.log(successLogMessage.trim());

            req.session.regenerate(() => { // Regenerate session ID on successful login
                req.session.userId = user._id;
                return res.redirect(user.isAdmin ? "/benefits" : "/dashboard");
            });
        });
    };

    this.displayLogoutPage = (req, res) => {
        req.session.destroy(() => res.redirect("/"));
    };

    this.displaySignupPage = (req, res) => {
        res.render("signup", {
            userName: "",
            password: "",
            passwordError: "",
            email: "",
            userNameError: "",
            emailError: "",
            verifyError: "",
            environmentalScripts
        });
    };

    const validateSignup = (userName, firstName, lastName, password, verify, email, errors) => {

        const USER_RE = /^.{1,20}$/;
        const FNAME_RE = /^.{1,100}$/;
        const LNAME_RE = /^.{1,100}$/;
        const EMAIL_RE = /^[\S]+@[\S]+\.[\S]+$/;
        const PASS_RE = /^.{1,20}$/;
        /*
        //Fix for A2-2 - Broken Authentication -  requires stronger password
        //(at least 8 characters with numbers and both lowercase and uppercase letters.)
        const PASS_RE =/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$/;
        */

        errors.userNameError = "";
        errors.firstNameError = "";
        errors.lastNameError = "";

        errors.passwordError = "";
        errors.verifyError = "";
        errors.emailError = "";

        if (!USER_RE.test(userName)) {
            errors.userNameError = "Invalid user name.";
            return false;
        }
        if (!FNAME_RE.test(firstName)) {
            errors.firstNameError = "Invalid first name.";
            return false;
        }
        if (!LNAME_RE.test(lastName)) {
            errors.lastNameError = "Invalid last name.";
            return false;
        }
        if (!PASS_RE.test(password)) {
            errors.passwordError = "Password must be 8 to 18 characters" +
                " including numbers, lowercase and uppercase letters.";
            return false;
        }
        if (password !== verify) {
            errors.verifyError = "Password must match";
            return false;
        }
        if (email !== "") {
            if (!EMAIL_RE.test(email)) {
                errors.emailError = "Invalid email address";
                return false;
            }
        }
        return true;
    };

    this.handleSignup = (req, res, next) => {

        const {
            email,
            userName,
            firstName,
            lastName,
            password,
            verify
        } = req.body;

        // set these up in case we have an error case
        const errors = {
            "userName": userName,
            "email": email
        };

        if (validateSignup(userName, firstName, lastName, password, verify, email, errors)) {

            userDAO.getUserByUserName(userName, (err, user) => {

                if (err) return next(err);

                if (user) {
                    errors.userNameError = "User name already in use. Please choose another";
                    return res.render("signup", {
                        ...errors,
                        environmentalScripts
                    });
                }

                userDAO.addUser(userName, firstName, lastName, password, email, (err, user) => {

                    if (err) return next(err);

                    //prepare data for the user
                    prepareUserData(user, next);
                    req.session.regenerate(() => {
                        req.session.userId = user._id;
                        // Set userId property. Required for left nav menu links
                        user.userId = user._id;

                        return res.render("dashboard", {
                            ...user,
                            environmentalScripts
                        });
                    });

                });
            });
        } else {
            console.log("user did not validate");
            return res.render("signup", {
                ...errors,
                environmentalScripts
            });
        }
    };

    this.displayWelcomePage = (req, res, next) => {
        let userId;

        if (!req.session.userId) {
            console.log("welcome: Unable to identify user...redirecting to login");
            return res.redirect("/login");
        }

        userId = req.session.userId;

        userDAO.getUserById(userId, (err, doc) => {
            if (err) return next(err);
            doc.userId = userId;
            return res.render("dashboard", {
                ...doc,
                environmentalScripts
            });
        });
    };
}

module.exports = SessionHandler;
