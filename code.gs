function Himaya() {
  var VTapiKey = '5641fe2ba079cbe16f4480bcbd26eccb894ddcb70a0af8853a85e6a383189a25';
  var threads = GmailApp.getInboxThreads(0, 2); // Process the first 2 threads
  
  for (var i = 0; i < threads.length; i++) {
    var messages = threads[i].getMessages();
    
    for (var j = 0; j < messages.length; j++) {
      var email = messages[j];
      Logger.log('Subject: ' + email.getSubject());

      // Check links
      var body = email.getPlainBody();
      var links = extractUrls(body);
      
      if (links.length > 0) {
        Logger.log('Links found: ' + links.join(', '));

        for (var l = 0; l < links.length; l++) {
          Utilities.sleep(15000); // 15 seconds delay
          var status = checkMaliciousLinksVT(links[l], VTapiKey);
          Logger.log('Link: ' + links[l] + ', Status: ' + status);
        }
      } else {
        Logger.log('No links found in this email.');
      }

      // Check attachments
      var attachments = email.getAttachments();
      if (attachments.length > 0) {
        Logger.log('Attachments found: ' + attachments.length);

        for (var a = 0; a < attachments.length; a++) {
          Utilities.sleep(15000); // 15 seconds delay
          var attachmentStatus = checkMaliciousAttachmentVT(attachments[a], VTapiKey);
          Logger.log('Attachment: ' + attachments[a].getName() + ', Status: ' + attachmentStatus);
        }
      } else {
        Logger.log('No attachments found in this email.');
      }
    }
  }
}

function extractUrls(text) {
  var regex = /(https?:\/\/[^\s]+)/g;
  var urls = [];
  var match;
  
  while ((match = regex.exec(text)) !== null) {
    urls.push(match[0]);
  }
  
  return urls;
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
      
      if (data.response_code === 1) {
        return data.positives > 0 ? "Malicious" : "Safe";
      } else {
        Logger.log('No report found for this link on VirusTotal: ' + link);
        return "Safe"; // Assuming safe if no report is found
      }
    } else {
      Logger.log('Error: HTTP ' + response.getResponseCode() + ' for link: ' + link);
      return "Safe"; // Assuming safe in case of error
    }
  } catch (e) {
    Logger.log('Error fetching VirusTotal data: ' + e.message + ' for link: ' + link);
    return "Safe"; // Assuming safe in case of error
  }
}

function checkMaliciousAttachmentVT(attachment, apiKey) {
  var reportUrl = 'https://www.virustotal.com/vtapi/v2/file/report';
  
  // Compute SHA-256 hash of the attachment
  var fileBlob = attachment.copyBlob();
  var fileBytes = fileBlob.getBytes();
  var sha256Hash = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, fileBytes);
  var hashHex = byteArrayToHex(sha256Hash);
  
  Logger.log('Computed hash for ' + attachment.getName() + ': ' + hashHex);

  var params = {
    'method': 'post',
    'contentType': 'application/x-www-form-urlencoded',
    'muteHttpExceptions': true,
    'payload': {
      'apikey': apiKey,
      'resource': sha256Hash
    }
  };

  try {
    var response = UrlFetchApp.fetch(reportUrl, params);
    
    if (response.getResponseCode() == 200) {
      var data = JSON.parse(response.getContentText());
      
      if (data.response_code === 1) {
        return data.positives > 0 ? "Malicious" : "Safe";
      } else {
        Logger.log('No report found for this attachment on VirusTotal: ' + attachment.getName());
        return "Unknown"; // File hasn't been scanned before
      }
    } else {
      Logger.log('Error: HTTP ' + response.getResponseCode() + ' for attachment: ' + attachment.getName());
      return "Error"; // Error occurred during checking
    }
  } catch (e) {
    Logger.log('Error fetching VirusTotal data: ' + e.message + ' for attachment: ' + attachment.getName());
    return "Error"; // Error occurred during checking
  }
}

function byteArrayToHex(byteArray) {
  return byteArray.map(function(byte) {
    return ('0' + (byte & 0xFF).toString(16)).slice(-2);
  }).join('');
}
