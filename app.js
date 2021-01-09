var express    = require( "express" );
var bodyParser = require( "body-parser" );
var mongoose   = require( "mongoose" );
var session    = require( "client-sessions" );
var bcrypt     = require( "bcryptjs" );
var app = express();
mongoose.connect( "mongodb://localhost/svcc", { useNewUrlParser: true, useUnifiedTopology: true } );
var Schema = mongoose.Schema;
var ObjectId = Schema.ObjectId;
var User = mongoose.model(
    "User",
    new Schema(
        {
            id:        ObjectId,
            firstName: String,
            lastName:  String,
            email:     { type: String, unique: true },
            password:  String
        }
    )
);
app.set( "view engine", "jade" );
app.use( bodyParser.urlencoded( { extended: true } ) );
app.use( bodyParser.json() );
app.use( session( {
    cookieName: "session",
    secret: "some_random_string",
    duration: 30 * 60 * 1000,
    activeDuration: 5 * 60 * 1000 //optional
} ) );
app.get( '/', function( req, res ) {
    res.render( "index.jade" );
} );
app.get( '/register', function( req, res ) {
    res.render( "register.jade" );
} );
// Creating users
app.post( '/register', function( req, res ) {
    var salt = bcrypt.genSaltSync( 10 );
    var hash = bcrypt.hashSync( req.body.password, salt );
    var user = new User( {
        firstName: req.body.firstName,
        lastName:  req.body.lastName,
        email:     req.body.email,
        password:  hash
    } );
    user.save( function( err ) {
        if ( err ) {
            var error = "Something bad happened! Please try again.";
            if ( err.code === 11000 ) {
                error = "That email is already taken, please try another.";
            };
            res.render( "register.jade", { error: error } );
        } else {
            req.session.user = user;
            res.redirect( "/dashboard" );
        };
    } );
} );
app.get( '/login', function( req, res ) {
    res.render( "login.jade" );
} );
app.post( '/login', function( req, res ) {
    User.findOne( { email: req.body.email }, function( err, user ) {
        if ( ! user ) {
            res.render( "login.jade", { error: "Incorrect email / password." } );
        } else {
            if ( bcrypt.compareSync( req.body.password, user.password ) ) {
                req.session.user = user;
                res.redirect( "/dashboard" );
            } else {
                res.render( "login.jade", { error: "Incorrect email / password." } );
            };
        };
    } );
} );
app.get( '/dashboard', function( req, res ) {
    if ( req.session && req.session.user ) {
        User.findOne( { email: req.session.user.email }, function( err, user ) {
            if ( ! user ) {
                req.session.reset();
                res.redirect( "/login" );
            } else {
                res.locals.user = user;
                res.render( "dashboard.jade" );
            };
        } );
    } else {
        res.redirect( "/login" );
    };
} );
app.listen( 3000 );
