// Empty constructor
function OktaPlugin() {}

// The function that passes work along to native shells
// Message is a string, duration may be 'long' or 'short'
OktaPlugin.prototype.show = function(successCallback, errorCallback) {
  cordova.exec(successCallback, errorCallback, 'OktaPlugin', 'InitializePlugin', null);
}

OktaPlugin.prototype.webAuthClient = function(successCallback, errorCallback) {
  cordova.exec(successCallback, errorCallback, 'OktaPlugin', 'webAuthClient', null);
}

OktaPlugin.prototype.authClient = function(user, pass, successCallback, errorCallback) {
  cordova.exec(successCallback, errorCallback, 'OktaPlugin', 'authClient', [user, pass]);
}

OktaPlugin.prototype.signIn = function(successCallback, errorCallback) {
  cordova.exec(successCallback, errorCallback, 'OktaPlugin', 'signIn', null);
}

// Installation constructor that binds ToastyPlugin to window
OktaPlugin.install = function() {
  if (!window.plugins) {
    window.plugins = {};
  }
  window.plugins.oktaPlugin = new OktaPlugin();
  return window.plugins.oktaPlugin;
};
cordova.addConstructor(OktaPlugin.install);
