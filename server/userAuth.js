'use strict'

const passport = require('passport')
const session = require('express-session')
const md5 = require('md5')
const SlackStrategy = require('passport-slack-oauth2').Strategy;

const log = require('./logger')
const {stringTemplate: template} = require('./utils')

const router = require('express-promise-router')()
const domains = new Set(process.env.APPROVED_DOMAINS.split(/,\s?/g))

passport.use(new SlackStrategy({
    clientID: process.env.SLACK_CLIENT_ID,
    clientSecret: process.env.SLACK_CLIENT_SECRET,
    skipUserProfile: false,
    callbackURL: process.env.SLACK_CALLBACK_URL,
    scope: ['identity.basic', 'identity.email', 'identity.avatar', 'identity.team']
  },
  (accessToken, refreshToken, profile, done) => {
    // optionally persist user data into a database
    done(null, profile);
  }
));

router.use(session({
  secret: process.env.SESSION_SECRET,
  resave: true,
  saveUninitialized: true
}))

router.use(passport.initialize())
router.use(passport.session())

// seralize/deseralization methods for extracting user information from the
// session cookie and adding it to the req.passport object
passport.serializeUser((user, done) => done(null, user))
passport.deserializeUser((obj, done) => done(null, obj))

router.get('/login', passport.authorize('Slack'));

router.get('/logout', (req, res) => {
  req.logout()
  res.redirect('/')
})

router.get('/auth/redirect',
  passport.authenticate('Slack', { failureRedirect: '/login' }),
  (req, res) => res.redirect(req.session.authRedirect || '/')
);

router.use((req, res, next) => {
  const isDev = process.env.NODE_ENV === 'development'
  const passportUser = (req.session.passport || {}).user || {}

  if (isDev || (req.isAuthenticated() && isAuthorized(passportUser))) {
    setUserInfo(req)
    return next()
  }

  if (req.isAuthenticated() && !isAuthorized(passportUser)) {
    return next(Error('Unauthorized'))
  }

  log.info('User not authenticated')
  req.session.authRedirect = req.path
  res.redirect('/login')
})

function isAuthorized(user) {
  return domains.has(user.team.domain);
}

function setUserInfo(req) {
  if (process.env.NODE_ENV === 'development') {
    req.userInfo = {
      email: process.env.TEST_EMAIL || template('footer.defaultEmail'),
      userId: '10',
      analyticsUserId: md5('10library')
    }
    return
  }
  req.userInfo = req.userInfo ? req.userInfo : {
    email: req.session.passport.user.displayName,
    userId: req.session.passport.user.user.id,
    analyticsUserId: md5(req.session.passport.user.user.id + 'library')
  }
}

module.exports = router
