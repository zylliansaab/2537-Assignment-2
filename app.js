require('./utils.js');
require('dotenv').config(); 
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const dns = require('node:dns');
const saltRounds = 12;

const app = express();

const Joi = require("joi");
// const mongoSanitizer = require('mongo-sanitizer').default;
//import mongoSanitizer from 'mongo-sanitizer';
const mongoSanitize = require('express-mongo-sanitize');


const PORT = process.env.PORT || 3000;
const expireTime = 1 * 60 * 60 * 1000; //expires after 1 hour  (hours * minutes * seconds * millis)
dns.setServers(['8.8.8.8', '8.8.4.4']);

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_user_database = process.env.MONGODB_USER_DATABASE;
const mongodb_session_database = process.env.MONGODB_SESSION_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

const {database} = include('databaseConnection');
const userCollection = database.db(mongodb_user_database).collection('users');

app.use(express.urlencoded({extended: false}));
app.use(express.json());

// app.use(mongoSanitizer(
//     { replaceWith: '_'}
// ));

//Hack for express 5.x not setting req.query as writable 
app.use((req, _res, next) => {
	Object.defineProperty(req, 'query', {
		...Object.getOwnPropertyDescriptor(req, 'query'),
		value: req.query,
		writable: true,
	});

	next();
})

app.use(mongoSanitize(
    {replaceWith: '%'}
));


var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_session_database}`,
	// crypto: {
	// 	secret: mongodb_session_secret,
	// }
});

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: false
}
));

app.get('/nosql-injection', (req,res) => {
    res.send(`
        noSQL injection example:
        <form action='/nosql-injection' method='post'>
            <input name='user' type='text' placeholder='user'>
            <button>Submit</button>
        </form>
        <div style='font-family:Helvetica, arial, sans-serif;'>
            You can use <a href="https://www.postman.com/">Postman <img src="Postman.png" style="height:45px;"/></a> to bypass this form page and perform a NoSQL injection attack.
            <br>
            <br>
            URL: <code>/nosql-injection</code> <br>
            Method: <code>POST</code> <br>
            Body (raw: JSON): <code> { "user": "name" } </code> <br>
            <em>(normal behaviour)</em> <br>
            <br>
            <strong>OR</strong> <br>
            <br>
            Body (raw: JSON): <code>{ "user": {"$ne": "name"} } </code><br>
            <em>(NoSQL injection attack)</em> <br>
            <img src="PostmanSS.png"/>
        </div>
        `)
});

app.post('/nosql-injection', async (req,res) => {
	var username = req.body.user;

	if (!username) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: ",username);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);

	//If we didn't use Joi to validate and check for a valid URL parameter below
	// we could run our userCollection.find and it would be possible to attack.
	// A URL parameter of user[$ne]=name would get executed as a MongoDB command
	// and may result in revealing information about all users or a successful
	// login without knowing the correct password.
	if (validationResult.error != null) {  
        console.log(validationResult.error);
        res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
        return;
	}	

	const result = await userCollection.find({username: username}).project({username: 1, pass: 1, _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

// Functions

// NO LONGER IN USE
// function getImage(id) {
//     if (id == 1) {
//         return "/apple.jpg";
//     }
//     else if (id == 2) {
//         return "/pineapple.jpg";
//     } 
//     else if (id == 3) {
//         return "/orange.jpg";
//     }
//     else {
//         return "Invalid id " + id;
//     }
// }

function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    } else {
    return false;
    }
}

function sessionValidation(req,res,next) {
    if (isValidSession(req)) {
        next();
    } else {
        res.redirect('/login');
    }
}

function isAdmin(req) {
    if (req.session.user_type == 'admin') {
        return true;
    } else {
    return false;
    }
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage.ejs", {error: "403 Not Authorized"} );
        return;
    }
    else {
        next();
    }
}

// Routes
app.get('/', (req, res) => {
    res.render("home.ejs", {req: req});
});

app.get('/signup', (req, res) => {
    res.render("signup.ejs")
});

app.post('/signupSubmit', async (req, res) => {

    var { name, email, password } = req.body;

    const schema = Joi.object(
		{
			name: Joi.string().alphanum().max(20).required(),
            email: Joi.string().max(20).required(),
			password: Joi.string().max(20).required()
		});

    const validate = schema.validate({ name, email, password })
    
    if (validate.error  != null) {
        const message = validate.error.details[0].message;
        res.send(`<h1>Error</h1><p>${message}</p><a href="/signup">Try again</a>`);
        return;
    }   else {
        var hashedPassword = await bcrypt.hash(password, saltRounds);
	
        await userCollection.insertOne({username: name, email: email, pass: hashedPassword, user_type: 'user'});
        req.session.authenticated = true;
		req.session.username = name;
        req.session.user_type = userCollection.user_type;
		req.session.cookie.maxAge = expireTime;

        console.log("User created!")
        res.redirect('/members');
        return;
    }  
});


app.get('/login', (req,res) => {
    res.render("login.ejs");
});

app.post('/loggingin', async (req,res) => {
    var em = req.body.email;
    var password = req.body.password;

	const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(em);
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/login");
	   return;
	}

	const result = await userCollection.find({email: em}).project({username: 1, email: 1, pass: 1, user_type: 1, _id: 1}).toArray();

	console.log(result);
	if (result.length != 1) {
        res.send(`
        <p>Email is wrong!<p>   
        <a href="/login">Go back</a>    
        `)
		return;
	}
	if (await bcrypt.compare(password, result[0].pass)) {
		req.session.authenticated = true;
		req.session.username = result[0].username;
        req.session.user_type = result[0].user_type;
		req.session.cookie.maxAge = expireTime;
        console.log("correct password");

		res.redirect('/members');
		return;
	} else {
        res.send(`
        <p>Password is wrong!<p>   
        <a href="/login">Go back</a>    
        `)
		return;
	}
});

app.get('/members', (req,res) => {
    if (req.session.authenticated) {
            res.render('members.ejs', {
        req: req,
        res: res,
        });
    } else {
        res.redirect('/');
    }
});

app.post('/logout', (req,res) => {
    req.session.authenticated = false;
	req.session.destroy();
    res.redirect('/');
});


app.get('/admin', sessionValidation, adminAuthorization, async (req,res) => {
    const result = await userCollection.find().project({username: 1, _id: 1, user_type: 1}).toArray();

    res.render("admin.ejs", {
        users: result});
});

app.post('/promote', async (req,res) => {
    const user = req.body.username;
    userCollection.updateOne({username: user}, {$set: {user_type: 'admin'}});
    
    if (user === req.session.username) {
        req.session.user_type = 'admin';
    }
    res.redirect('/admin');
})

app.post('/demote', async (req,res) => {
    const user = req.body.username;
    userCollection.updateOne({username: user}, {$set: {user_type: 'user'}});

    if (user === req.session.username) {
        req.session.user_type = 'user';
    }
    res.redirect('/admin');
})

app.use(express.static(__dirname + "/public"));

app.use((req,res) => {
	res.status(404);
	res.send("Page not found - 404");
});

// Start server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});