"use strict";

const cors = require('cors');

const helmet = require('helmet'); 

const express = require("express");
const favicon = require("serve-favicon");
const bodyParser = require("body-parser");
const session = require("express-session");
// const csrf = require('csurf');
const consolidate = require("consolidate"); // Templating library adapter for Express
const swig = require("swig");
// const helmet = require("helmet");
const MongoClient = require("mongodb").MongoClient; // Driver for connecting to MongoDB
const http = require("http");
const marked = require("marked");
//const nosniff = require('dont-sniff-mimetype');

const routes = require("./app/routes");
const { port, db, cookieSecret } = require("./config/config"); // Application config properties

const rateLimit = require('express-rate-limit');   

const app = express();  

app.use(helmet()); 

const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, 
  max: 5000, 
  message:
    "Too many requests from this IP, please try again after 1 minutes",
  standardHeaders: true, 
  legacyHeaders: false, 
});



const corsOptions = {
  origin: 'http://localhost',
  methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
  credentials: true, 
  optionsSuccessStatus: 204 
};

 
app.use(cors(corsOptions));

// app.use(limiter);


// --- 1. Mock API Key Storage ---
const VALID_API_KEYS = [
    { key: "NG_API_KEY_DEV_123", description: "Development Team Key", permissions: ["read", "write"] },
    { key: "NG_API_KEY_ANALYTICS_456", description: "Analytics Dashboard Key", permissions: ["read"] }
];

// --- 2. API Key Authentication Middleware ---
function authenticateApiKey(req, res, next) {
    
    const apiKey = req.headers['x-api-key'] || req.query.api_key;

    if (!apiKey) {
        return res.status(401).json({ message: "Access Denied: API Key missing." });
    }

    const foundKey = VALID_API_KEYS.find(validKey => validKey.key === apiKey);

    if (foundKey) {
        req.apiKeyInfo = foundKey;
        console.log(`API Key authenticated: ${foundKey.description}`);
        next(); 
    } else {
        console.log("API Key provided is invalid.");
        res.status(403).json({ message: "Access Denied: Invalid API Key." });
    }
}

// ----------------------------------------------------
// Content Security Policy (CSP)
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://trusted-cdn.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      imgSrc: ["'self'", "data:"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      connectSrc: ["'self'", "ws://localhost:4000"],
      objectSrc: ["'none'"],
    },
  })
);
// ----------------------------------------------------


app.use(
  helmet.hsts({
    maxAge: 31536000, 
    includeSubDomains: true, 
    preload: true 
  })
);


/*
// Fix for A6-Sensitive Data Exposure
// Load keys for establishing secure HTTPS connection
const fs = require("fs");
const https = require("https");
const path = require("path");
const httpsOptions = {
    key: fs.readFileSync(path.resolve(__dirname, "./artifacts/cert/server.key")),
    cert: fs.readFileSync(path.resolve(__dirname, "./artifacts/cert/server.crt"))
};
*/

MongoClient.connect(db, (err, db) => {
    if (err) {
        console.log("Error: DB: connect");
        console.log(err);
        process.exit(1);
    }
    console.log(`Connected to the database`);

    /*
    // Fix for A5 - Security MisConfig
    // TODO: Review the rest of helmet options, like "xssFilter"
    // Remove default x-powered-by response header
    app.disable("x-powered-by");

    // Prevent opening page in frame or iframe to protect from clickjacking
    app.use(helmet.frameguard()); //xframe deprecated

    // Prevents browser from caching and storing page
    app.use(helmet.noCache());

    // Allow loading resources only from white-listed domains
    app.use(helmet.contentSecurityPolicy()); //csp deprecated

    // Allow communication only on HTTPS
    app.use(helmet.hsts());

    // TODO: Add another vuln: https://github.com/helmetjs/helmet/issues/26
    // Enable XSS filter in IE (On by default)
    // app.use(helmet.iexss());
    // Now it should be used in hit way, but the README alerts that could be
    // dangerous, like specified in the issue.
    // app.use(helmet.xssFilter({ setOnOldIE: true }));

    // Forces browser to only use the Content-Type set in the response header instead of sniffing or guessing it
    app.use(nosniff());
    */

    // Adding/ remove HTTP Headers for security
    app.use(favicon(__dirname + "/app/assets/favicon.ico"));

    // Express middleware to populate "req.body" so we can access POST variables
    app.use(bodyParser.json());
    app.use(bodyParser.urlencoded({
        // Mandatory in Express v4
        extended: false
    }));

    // Enable session management using express middleware
    app.use(session({
        // genid: (req) => {
        //    return genuuid() // use UUIDs for session IDs
        //},
        secret: cookieSecret,
        // Both mandatory in Express v4
        saveUninitialized: true,
        resave: true
        /*
        // Fix for A5 - Security MisConfig
        // Use generic cookie name
        key: "sessionId",
        */

        /*
        // Fix for A3 - XSS
        // TODO: Add "maxAge"
        cookie: {
            httpOnly: true
            // Remember to start an HTTPS server to get this working
            // secure: true
        }
        */

    }));

    /*
    // Fix for A8 - CSRF
    // Enable Express csrf protection
    app.use(csrf());
    // Make csrf token available in templates
    app.use((req, res, next) => {
        res.locals.csrftoken = req.csrfToken();
        next();
    });
    */

    // Register templating engine
    app.engine(".html", consolidate.swig);
    app.set("view engine", "html");
    app.set("views", `${__dirname}/app/views`);
    // Fix for A5 - Security MisConfig
    // TODO: make sure assets are declared before app.use(session())
    app.use(express.static(`${__dirname}/app/assets`));


    // Initializing marked library
    // Fix for A9 - Insecure Dependencies
    marked.setOptions({
        sanitize: true
    });
    app.locals.marked = marked;



// --- 3. Apply the API Key Middleware to specific API routes ---

    app.get('/api/status', authenticateApiKey, (req, res) => {
        
        console.log("Serving /api/status request.");
        res.json({
            status: "Operational",
            message: "NodeGoat API is running smoothly.",
            timestamp: new Date().toISOString(),
            accessedBy: req.apiKeyInfo ? req.apiKeyInfo.description : 'Unknown'
        });
    });






    // Application routes
    routes(app, db);

    // Template system setup
    swig.setDefaults({
        // Autoescape disabled
        autoescape: false
        /*
        // Fix for A3 - XSS, enable auto escaping
        autoescape: true // default value
        */
    });

    // Insecure HTTP connection
    http.createServer(app).listen(port, () => {
        console.log(`Express http server listening on port ${port}`);
    });

    /*
    // Fix for A6-Sensitive Data Exposure
    // Use secure HTTPS protocol
    https.createServer(httpsOptions, app).listen(port, () => {
        console.log(`Express http server listening on port ${port}`);
    });
    */

});
