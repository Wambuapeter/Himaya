function onGmailAuthorization(e) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle("Access Granted"))
    .addSection(CardService.newCardSection()
      .addWidget(CardService.newTextParagraph()
        .setText("You have successfully granted Himaya access to your Gmail account. We are the 'Hushed Protector of Health Data' and your data is safe with us!")))
    .build();
}

function onGmailMessageOpen(e) {
  var messageId = e.messageMetadata.messageId;  // Access to messageId
  var accessToken = e.gmail.accessToken;
  
  GmailApp.setCurrentMessageAccessToken(accessToken);
  
  var message = GmailApp.getMessageById(messageId);
  var result = Himaya(message);  // Passing the message to Himaya
  
  // If malicious content is detected
  if (result.isMalicious) {
    return createAlertCard(result.reason);
  }
  
  // If there are no links or attachments in the email
  if (result.noLinksOrAttachments) {
    return createSafeEmailCard("Safe email: No links or attachments found.");
  }
  
  // If there are links or attachments, but none are malicious
  if (!result.isMalicious && result.hasLinksOrAttachments) {
    return createSafeEmailCard("Safe email: No Ransomware detected.");
  }

  // Default: do nothing (no card displayed)
  return null;
}

function onGmailHomePageOpen(e) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle("Welcome to Himaya"))
    .addSection(CardService.newCardSection()
      .addWidget(CardService.newTextParagraph()
        .setText("Himaya is protecting your inbox. Open an email to scan for threats.")))
    .build();
}

// Function to scan all threads, not just inbox
function scanAllEmails() {
  var threads = GmailApp.getInboxThreads();  // Get all inbox threads
  
  for (var i = 0; i < threads.length; i++) {
    var messages = threads[i].getMessages();
    
    for (var j = 0; j < messages.length; j++) {
      var result = Himaya(messages[j]);  // Scan each message
      if (result.isMalicious) {
        createAlertCard(result.reason);  // Show alert for malicious content
      }
    }
  }
}

function Himaya(email) {
  var VTapiKey = '';
  var MBapiKey = '';
  var OTXapiKey = '';
  
  var isMalicious = false;
  var maliciousReason = '';
  var hasLinksOrAttachments = false;
  var noLinksOrAttachments = true;

  // Check email body for links
  var body = email.getPlainBody();
  var links = extractUrls(body);
  
  if (links.length > 0) {
    noLinksOrAttachments = false;  // There are links in the email
    hasLinksOrAttachments = true;
    for (var l = 0; l < links.length; l++) {
      Utilities.sleep(15000);  // To avoid rate limiting
      if (checkLink(links[l], VTapiKey, OTXapiKey)) {
        isMalicious = true;
        maliciousReason = 'RANSOMWARE ASSOCIATED LINK💀🚨';
        break;
      }
    }
  }

  // Check attachments if no malicious links found
  if (!isMalicious) {
    var attachments = email.getAttachments();
    if (attachments.length > 0) {
      noLinksOrAttachments = false;  // There are attachments in the email
      hasLinksOrAttachments = true;
      for (var a = 0; a < attachments.length; a++) {
        Utilities.sleep(15000);  // Avoid rate limiting
        if (checkAttachment(attachments[a], VTapiKey, OTXapiKey, MBapiKey)) {
          isMalicious = true;
          maliciousReason = 'RANSOMWARE ASSOCIATED ATTACHMENT💀🚨';
          break;
        }
      }
    }
  }

  return { 
    isMalicious: isMalicious, 
    reason: maliciousReason, 
    hasLinksOrAttachments: hasLinksOrAttachments, 
    noLinksOrAttachments: noLinksOrAttachments 
  };
}

function createAlertCard(reason) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle("**⚠️ ALERT: 💀Ransomware💀 🚨🔴Detected🔴🚨 ⚠️**")
      .setImageStyle(CardService.ImageStyle.SQUARE)
      .setImageUrl("https://www.iconsdb.com/icons/preview/red/warning-xxl.png"))
    .addSection(CardService.newCardSection()
      .addWidget(CardService.newTextParagraph()
        .setText(reason))
      .addWidget(CardService.newTextParagraph()
        .setText("1. ⛔️🚫Do not🙅🏽 click on any attached link or attachment.🚫⛔️\n"
                  + "2. 🤙🏼Immediately contact your hospital’s cybersecurity/IT specialist for further assistance.🤙🏼")))
    .setFixedFooter(CardService.newFixedFooter()
      .setPrimaryButton(CardService.newTextButton()
        .setText("Dismiss")
        .setOnClickAction(CardService.newAction().setFunctionName("dismissAlert"))))
    .build();
}

function createSafeEmailCard(text) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle("✅ Safe Email"))
    .addSection(CardService.newCardSection()
      .addWidget(CardService.newTextParagraph()
        .setText(text)))
    .build();
}

function dismissAlert() {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().popCard())
    .build();
}

function extractUrls(text) {
  var regex = /(https?:\/\/[^\s]+)/g;
  return text.match(regex) || [];
}

function checkLink(link, VTapiKey, OTXapiKey) {
  return checkMaliciousLinksVT(link, VTapiKey) || checkOTX(link, OTXapiKey, 'url');
}

function checkAttachment(attachment, VTapiKey, OTXapiKey, MBapiKey) {
  var fileBlob = attachment.copyBlob();
  var fileBytes = fileBlob.getBytes();
  var sha256Hash = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, fileBytes);
  var hashHex = byteArrayToHex(sha256Hash);

  return checkMaliciousAttachmentVT(hashHex, VTapiKey) || 
         checkOTX(hashHex, OTXapiKey, 'file') || 
         checkMaliciousAttachmentMB(hashHex, MBapiKey);
}

function checkMaliciousLinksVT(link, apiKey) {
  var scanUrl = 'https://www.virustotal.com/vtapi/v2/url/report';
  var params = {
    'method': 'post',
    'contentType': 'application/x-www-form-urlencoded',
    'muteHttpExceptions': true,
    'payload': {
      'apikey': apiKey,
      'resource': link
    }
  };
  
  try {
    var response = UrlFetchApp.fetch(scanUrl, params);
    if (response.getResponseCode() == 200) {
      var data = JSON.parse(response.getContentText());
      return data.response_code === 1 && data.positives > 0;
    }
  } catch (e) {
    // Error handling
  }
  return false;
}

function checkMaliciousAttachmentVT(hashHex, apiKey) {
  var reportUrl = 'https://www.virustotal.com/vtapi/v2/file/report';
  var params = {
    'method': 'post',
    'contentType': 'application/x-www-form-urlencoded',
    'muteHttpExceptions': true,
    'payload': {
      'apikey': apiKey,
      'resource': hashHex
    }
  };

  try {
    var response = UrlFetchApp.fetch(reportUrl, params);
    if (response.getResponseCode() == 200) {
      var data = JSON.parse(response.getContentText());
      return data.response_code === 1 && data.positives > 0;
    }
  } catch (e) {
    // Error handling
  }
  return false;
}

function byteArrayToHex(byteArray) {
  return byteArray.map(function(byte) {
    return ('0' + (byte & 0xFF).toString(16)).slice(-2);
  }).join('');
}

function checkMaliciousAttachmentMB(hashHex, apiKey) {
  var reportUrl = 'https://mb-api.abuse.ch/api/v1/';
  var payload = {
    'query': 'get_info',
    'hash': hashHex
  };
  var options = {
    'method': 'post',
    'contentType': 'application/json',
    'muteHttpExceptions': true,
    'payload': JSON.stringify(payload)
  };

  try {
    var response = UrlFetchApp.fetch(reportUrl, options);
    if (response.getResponseCode() == 200) {
      var data = JSON.parse(response.getContentText());
      return data.query_status === "ok";
    }
  } catch (e) {
    // Error handling
  }
  return false;
}

function checkOTX(indicator, apiKey, type) {
  var baseUrl = 'https://otx.alienvault.com/api/v1/indicators/';
  var endpoint = type === 'url' ? 'url/general' : 'file/general';
  var url = baseUrl + endpoint + '/' + (type === 'url' ? encodeURIComponent(indicator) : indicator);

  var params = {
    'method': 'get',
    'headers': {
      'X-OTX-API-KEY': apiKey
    },
    'muteHttpExceptions': true
  };

  try {
    var response = UrlFetchApp.fetch(url, params);
    if (response.getResponseCode() == 200) {
      var data = JSON.parse(response.getContentText());
      return data.pulse_info && data.pulse_info.count > 0;
    }
  } catch (e) {
    // Error handling
  }
  return false;
}

