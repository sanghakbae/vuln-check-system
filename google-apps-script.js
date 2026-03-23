var DOMAIN_SHEET_NAME = "domains";
var DOMAIN_HEADERS = ["id", "domain", "serviceName", "serviceType", "servicePurpose"];
var SCAN_SHEET_NAME = "scan_results";
var SCAN_HEADERS = ["domain", "scannedAt", "resultJson"];

function doGet(e) {
  var action = (e && e.parameter && e.parameter.action) || "list";

  try {
    if (action === "list") {
      return jsonResponse({
        ok: true,
        items: listDomains_(),
      });
    }

    if (action === "listScans") {
      return jsonResponse({
        ok: true,
        items: listScans_(),
      });
    }

    return jsonResponse({
      ok: false,
      error: "unsupported_action",
    });
  } catch (error) {
    return jsonResponse({
      ok: false,
      error: "list_failed",
      message: error.message,
    });
  }
}

function doPost(e) {
  try {
    var payload = JSON.parse((e && e.postData && e.postData.contents) || "{}");
    var action = payload.action || "upsert";

    if (action === "upsert") {
      return jsonResponse({
        ok: true,
        item: upsertDomain_(payload.item || {}),
      });
    }

    if (action === "upsertScan") {
      return jsonResponse({
        ok: true,
        item: upsertScan_(payload.item || {}),
      });
    }

    return jsonResponse({
      ok: false,
      error: "unsupported_action",
    });
  } catch (error) {
    return jsonResponse({
      ok: false,
      error: "upsert_failed",
      message: error.message,
    });
  }
}

function listDomains_() {
  var sheet = getOrCreateSheet_(DOMAIN_SHEET_NAME, DOMAIN_HEADERS);
  var values = sheet.getDataRange().getValues();

  return values.slice(1).map(function (row) {
    return {
      id: String(row[0] || ""),
      domain: String(row[1] || ""),
      serviceName: String(row[2] || ""),
      serviceType: String(row[3] || ""),
      servicePurpose: String(row[4] || ""),
    };
  }).filter(function (row) {
    return row.id && row.domain;
  });
}

function upsertDomain_(item) {
  if (!item.id || !item.domain) {
    throw new Error("id and domain are required");
  }

  var sheet = getOrCreateSheet_(DOMAIN_SHEET_NAME, DOMAIN_HEADERS);
  var values = sheet.getDataRange().getValues();
  var rowIndex = findRowIndex_(values, 0, item.id);
  var row = [
    String(item.id || ""),
    String(item.domain || ""),
    String(item.serviceName || ""),
    String(item.serviceType || ""),
    String(item.servicePurpose || ""),
  ];

  writeRow_(sheet, rowIndex, row);
  return {
    id: row[0],
    domain: row[1],
    serviceName: row[2],
    serviceType: row[3],
    servicePurpose: row[4],
  };
}

function listScans_() {
  var sheet = getOrCreateSheet_(SCAN_SHEET_NAME, SCAN_HEADERS);
  var values = sheet.getDataRange().getValues();

  return values.slice(1).map(function (row) {
    return {
      domain: String(row[0] || ""),
      scannedAt: String(row[1] || ""),
      result: parseJson_(row[2]),
    };
  }).filter(function (row) {
    return row.domain;
  });
}

function upsertScan_(item) {
  if (!item.domain || !item.result) {
    throw new Error("domain and result are required");
  }

  var sheet = getOrCreateSheet_(SCAN_SHEET_NAME, SCAN_HEADERS);
  var values = sheet.getDataRange().getValues();
  var rowIndex = findRowIndex_(values, 0, item.domain);
  var row = [
    String(item.domain || ""),
    String(item.scannedAt || ""),
    JSON.stringify(item.result || {}),
  ];

  writeRow_(sheet, rowIndex, row);
  return {
    domain: row[0],
    scannedAt: row[1],
    result: item.result,
  };
}

function getOrCreateSheet_(sheetName, headers) {
  var spreadsheet = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = spreadsheet.getSheetByName(sheetName);

  if (!sheet) {
    sheet = spreadsheet.insertSheet(sheetName);
  }

  ensureHeaders_(sheet, headers);
  return sheet;
}

function ensureHeaders_(sheet, headers) {
  var range = sheet.getRange(1, 1, 1, headers.length);
  var firstRow = range.getValues()[0];
  var same = headers.every(function (header, index) {
    return String(firstRow[index] || "") === header;
  });

  if (!same) {
    range.setValues([headers]);
  }
}

function findRowIndex_(values, columnIndex, lookupValue) {
  for (var i = 1; i < values.length; i += 1) {
    if (String(values[i][columnIndex]) === String(lookupValue)) {
      return i + 1;
    }
  }

  return -1;
}

function writeRow_(sheet, rowIndex, row) {
  if (rowIndex === -1) {
    sheet.appendRow(row);
  } else {
    sheet.getRange(rowIndex, 1, 1, row.length).setValues([row]);
  }
}

function parseJson_(value) {
  try {
    return JSON.parse(String(value || "{}"));
  } catch (error) {
    return {};
  }
}

function jsonResponse(payload) {
  return ContentService
    .createTextOutput(JSON.stringify(payload))
    .setMimeType(ContentService.MimeType.JSON);
}
