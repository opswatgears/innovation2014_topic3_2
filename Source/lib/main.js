var tmr = require('sdk/timers');
var Request = require("sdk/request").Request;
var buttons = require('sdk/ui/button/action');
var selfSDK = require("sdk/self");
var tabsSDK = require("sdk/tabs");
var pageModSDK = require("sdk/page-mod");

var {
	env
}
	 = require('sdk/system/environment');
const {
	components
}
	 = require("chrome");
const {
	Cc,
	Ci,
	Cu
}
	 = require("chrome");

Cu.import("resource://gre/modules/FileUtils.jsm");
Cu.import("resource://gre/modules/NetUtil.jsm");

function IPDetective() {}
IPDetective.prototype.findAllSuspiciousIpsAsync = function (asyncFunction) { // asyncFunction(suspiciousIps)
}

function IPWindowsDetective() {
	IPDetective.call(this)
	this.cmdEXE = FileUtils.getFile("ProfD", ["extensions", selfSDK.id, 'resources', selfSDK.name, 'data', "NoConsoleApp.exe"]);
	// console.log(this.cmdEXE.path);

	this.tempFileObj = FileUtils.getFile("ProfD", ["netstatVal.txt"]);
	this.tempFileObj.createUnique(Ci.nsIFile.NORMAL_FILE_TYPE, FileUtils.PERMS_FILE);
}

IPWindowsDetective.prototype = Object.create(IPDetective.prototype);
IPWindowsDetective.prototype.constructor = IPWindowsDetective;
IPWindowsDetective.prototype.findAllSuspiciousIpsAsync = function (asyncFunction) {
	var process = Cc["@mozilla.org/process/util;1"].createInstance(Ci.nsIProcess);
	process.init(this.cmdEXE);

	//var args = ['/c netstat -n > ' + this.tempFileObj.path]
	var args = ['netstat -n', this.tempFileObj.path];
	process.run(true, args, args.length);

	NetUtil.asyncFetch(this.tempFileObj, function (inputStream, status) {
		suspiciousIPs = []
		if (!components.isSuccessCode(status)) {
			console.log("Error File")
			asyncFunction([])
			return;
		}

		// The file data is contained within inputStream.
		// You can read it into a string with
		var data = NetUtil.readInputStreamToString(inputStream, inputStream.available());
		regObj = /\d\s+(\d+\.\d+\.\d+\.\d+):/g;
		while (match = regObj.exec(data)) {
			ip = match[1]
				if (ip != '127.0.0.1' && (ip < '172.16.0.0' || ip > '172.31.0.0') && (ip < '192.168.0.0' || ip > '192.168.255.0')) { // Get Public IP Only
					suspiciousIPs.push(match[1]);
				}
		}
		var unique = suspiciousIPs.filter(function onlyUnique(value, index, self) {
				return self.indexOf(value) === index;
			});
		asyncFunction(unique)
	});
}

function IPer(address, scanDetails) {
	this.scanDetails = scanDetails;
	this.address = address;
	this.ImgLink = "images/check.png";
	this.AltImg = "check button";
}

function WantedIPer(address, scanDetails) {
	IPer.call(this, address, scanDetails);
	this.ImgLink = "images/error.png";
	this.AltImg = "error button";
}
WantedIPer.prototype = Object.create(IPer.prototype);
WantedIPer.prototype.constructor = IPer.constructor;

function ErrorIPer(address, errorResponse) {
	IPer.call(this, address, {
		error_code : errorResponse.status,
		error_text : errorResponse.statusText
	});
	this.ImgLink = "images/alert.png";
	this.AltImg = "Aborted";
}
WantedIPer.prototype = Object.create(IPer.prototype);
WantedIPer.prototype.constructor = IPer.constructor;

function IPPolice(apiKey) {
	this.apiKey = apiKey;
}
IPPolice.prototype.scan = function (suspiciousIP, options) { // options = {scanSuccess : function(iper), scanFail : function(response)}
	options = options || {};
	options.scanSuccess = options.scanSuccess || function (iper) {};
	options.scanFail = options.scanFail || function (response) {};

	Request({
		url : "https://ipscan.metascan-online.com/v1/scan/" + suspiciousIP,
		headers : {
			apikey : this.apiKey
		}, // ec43896f7a6595bf4c5a4e0467a3cc3d
		onComplete : function (response) {
			scanDetails = response.json;
			iper = {};
			if (scanDetails === null) {
				options.scanFail(response);
				return;
			} else if (scanDetails.detected_by !== 0)
				iper = new WantedIPer(suspiciousIP, scanDetails);
			else
				iper = new IPer(suspiciousIP, scanDetails);
			options.scanSuccess(iper);
		},
	}).get();
}

IPPolice.prototype.scanAll = function (suspiciousIPs, options) {
	options = options || {};
	options.scanSuccess = options.scanSuccess || function (i, iper) {};
	options.scanFail = options.scanFail || function (i, response) {};

	for (var i = 0; i < suspiciousIPs.length; i++) {
		this.scan(suspiciousIPs[i], {
			scanSuccess : (function (ipIndex) {
				return function (iper) {
					options.scanSuccess(ipIndex, iper);
				};
			})(i),
			scanFail : (function (ipIndex) {
				return function (response) {
					options.scanFail(ipIndex, response);
				};
			})(i)
		});
	}
}

var IPScanBtnState = {};

IPScanBtnState.WaitToScanState = function () {
	this.icon = {
		"16" : "./images/icon.png",
		"32" : "./images/icon.png",
		"64" : "./images/icon.png"
	};

	this.onClick = function (ipScanBtn) {
		return function f(state) {
			ipScanBtn.removeListener("click", f);
			var newState = new IPScanBtnState.WaitScanningState();
			newState.setState(ipScanBtn);
			
			
		}
	};
}
IPScanBtnState.WaitToScanState.prototype.setState = function(ipScanBtn) {
	ipScanBtn.icon = this.icon;
	ipScanBtn.on("click", this.onClick(ipScanBtn));
}

IPScanBtnState.WaitScanningState = function (){
	
	IPScanBtnState.WaitToScanState.call(this);
	
	this.icon = {
				"16" : "./images/loading-16.gif",
				"32" : "./images/loading-32.gif",
			};
			
	this.onClick = function(ipScanBtn){
		var ipDetectiveObj = new IPWindowsDetective();
		var ipPolice = new IPPolice(require("sdk/simple-prefs").prefs.MScanOnlineAPIKey);

		ipDetectiveObj.findAllSuspiciousIpsAsync(function (ips) {
			console.log("IP List Len " + ips.length);
			for (var i = 0; i < ips.length; i++) {
				console.log("IP: " + ips[i]);
			}

			var scannedIpers = new Array();
			function checkScanComplete() {
				if (scannedIpers.length === ips.length) {
					
					var newState = new IPScanBtnState.FinishScanningState(scannedIpers);
					newState.setState(ipScanBtn);
				}
			}
			
			checkScanComplete(); // Check if IP list is empty

			ipPolice.scanAll(ips, {
				scanSuccess : function (i, iper) {
					scannedIpers.push(iper);
					checkScanComplete();
				},
				scanFail : function (i, response) {
					scannedIpers.push(new ErrorIPer(ips[i], response));
					// console.log("Index: " + i);
					// console.log("HTTP Status Code: " + response.status);
					// console.log("HTTP Status: " + response.statusText);
					checkScanComplete();
				}
			});
		});
	
		return function f(state){
			ipScanBtn.removeListener("click", f);
		};
	}
}
IPScanBtnState.WaitScanningState.prototype = Object.create(IPScanBtnState.WaitToScanState.prototype);
IPScanBtnState.WaitScanningState.prototype.constructor = IPScanBtnState.WaitToScanState;

IPScanBtnState.FinishScanningState = function(scannedIpers){
	IPScanBtnState.WaitToScanState.call(this);
	this.icon = "./images/scanning-finish.gif";
	
	this.onClick = function(ipScanBtn){
		return function f(state){
			ipScanBtn.removeListener("click", f);
			
			var wantedDetailsIper = "";
			// pageModSDK.PageMod({
				// include : selfSDK.data.url("details.html"),
				// contentScriptFile : [selfSDK.data.url('scripts/web.js')],
				// // contentScriptWhen : 'start',
				// onAttach : function (worker) {
					// worker.port.emit('SetScanDetails', wantedDetailsIper);
				// }
			// });

			tabsSDK.open({
				url : selfSDK.data.url("result.html"),
				onReady : function onReady(tab) {

					if (tab.url !== selfSDK.data.url("result.html"))
						return;

					var worker = tab.attach({
							contentScriptFile : [selfSDK.data.url('scripts/web.js')],
						});
					worker.port.emit('SetScannedIPers', scannedIpers);

					worker.port.on('ClickDetailEvent', function (iper) {
						wantedDetailsIper = iper;
						tab.on("ready", function(tab){
							var worker = tab.attach({
								  contentScriptFile : [selfSDK.data.url('scripts/web.js')],
							});
							worker.port.emit('SetScanDetails', wantedDetailsIper);
						});
						tab.url = selfSDK.data.url("details.html");
					});
				},
			});
			
			var newState = new IPScanBtnState.WaitToScanState();
			newState.setState(ipScanBtn);
		}
	};
}

IPScanBtnState.FinishScanningState.prototype = Object.create(IPScanBtnState.WaitToScanState.prototype);
IPScanBtnState.FinishScanningState.prototype.constructor = IPScanBtnState.WaitToScanState;

var button = buttons.ActionButton({
		id : "ip-scan",
		label : "IP Scan All",
		icon : {
				"16" : "./images/icon.png",
				"32" : "./images/icon.png",
				"64" : "./images/icon.png"
			},
		onClick : function(state){},
});

(new IPScanBtnState.WaitToScanState()).setState(button);

