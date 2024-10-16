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
  
  // Only show the alert card if malicious content is detected
  if (result.isMalicious) {
    return createAlertCard(result.reason);
  } 
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

function Himaya(email) {
  var VTapiKey = '5641fe2ba079cbe16f4480bcbd26eccb894ddcb70a0af8853a85e6a383189a25';
  var MBapiKey = '3e4f0e95596ba839ea2351e7310ee8d6';
  var OTXapiKey = '2e9754525c7697acf8fb7d25dff7435b31e7639f32f916148cbcc004b98d6673';
  
  var isMalicious = false;
  var maliciousReason = '';

  // Check email body for links
  var body = email.getPlainBody();
  var links = extractUrls(body);
  
  for (var l = 0; l < links.length; l++) {
    Utilities.sleep(15000);  // To avoid rate limiting
    if (checkLink(links[l], VTapiKey, OTXapiKey)) {
      isMalicious = true;
      maliciousReason = 'RANSOMWARE ASSOCIATED LINK';
      break;
    }
  }

  // Check attachments if no malicious links found
  if (!isMalicious) {
    var attachments = email.getAttachments();
    for (var a = 0; a < attachments.length; a++) {
      Utilities.sleep(15000);  // Avoid rate limiting
      if (checkAttachment(attachments[a], VTapiKey, OTXapiKey, MBapiKey)) {
        isMalicious = true;
        maliciousReason = 'RANSOMWARE ASSOCIATED ATTACHMENT';
        break;
      }
    }
  }

  return { isMalicious: isMalicious, reason: maliciousReason };
}

function createAlertCard(reason) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle("⚠️ ALERT: Malicious Content Detected ⚠️")
      .setImageStyle(CardService.ImageStyle.SQUARE)
      .setImageUrl("https://www.gstatic.com/images/icons/material/system/1x/warning_red_48dp.png"))
    .addSection(CardService.newCardSection()
      .addWidget(CardService.newTextParagraph()
        .setText("Malicious email detected: " + reason))  // Removed setTextAlignment
      .setCollapsible(false)
      .setNumUncollapsibleWidgets(1))
    .setFixedFooter(CardService.newFixedFooter()
      .setPrimaryButton(CardService.newTextButton()
        .setText("Dismiss")
        .setOnClickAction(CardService.newAction().setFunctionName("dismissAlert"))))
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
