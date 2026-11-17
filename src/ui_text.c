#include "ui_text.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef __APPLE__
#include <CoreFoundation/CoreFoundation.h>
#endif

static const ui_text german = {
    .strings = {
        .domain_label = "Domain",
        .domain_error = "Bitte eine gültige Domain eingeben.",
        .extra_names_label = "Weitere Namen (optional)",
        .extra_names_hint = "Subdomains und DKIM-Selektoren, die zusätzlich abgefragt werden.",
        .look_up_button = "Abfragen",
        .page_records = "DNS-Einträge",
        .page_dmarc = "DMARC erstellen",
        .page_reports = "DMARC-Berichte",

        .looking_up = "DNS wird abgefragt …",
        .no_lookup_title = "Noch keine Abfrage",
        .no_lookup_description = "Domain eingeben und „Abfragen“ drücken. Abgefragt werden A, AAAA, CNAME, MX, NS, "
                                 "TXT, SOA und CAA der Domain, dazu www, gängige DKIM-Selektoren (auch Hetzners "
                                 "default<JJMM>) und die weiteren Namen.",
        .present = "vorhanden",
        .missing = "fehlt",
        .name_unknown = "Name unbekannt",
        .incoming_mail_card = "E-Mail-Empfang",
        .no_mail_exchanger = "Kein MX-Eintrag gefunden.",
        .no_spf = "Kein TXT-Eintrag mit v=spf1.",
        .no_dmarc = "Kein Eintrag unter _dmarc. Im Tab „DMARC erstellen“ anlegen.",
        .unknown_dkim_selectors = "Unter _domainkey gibt es Selektoren, aber keiner der geprüften Namen. Den Selektor "
                                  "beim Mail-Anbieter nachsehen und unter „Weitere Namen“ als <selektor>._domainkey "
                                  "eintragen.",
        .column_type = "Typ",
        .column_name = "Name",
        .column_ttl = "TTL (s)",
        .column_value = "Wert",
        .source_resolver = "Kein Nameserver der Zone erreichbar; abgefragt über den Systemresolver, der Einträge bis "
                           "zu ihrer TTL zwischenspeichert.",
        .some_queries_failed = "Nicht alle Abfragen waren erfolgreich",
        .no_records_found = "Keine Einträge gefunden",
        .status_no_data = "Die Domain hat keine Einträge der abgefragten Typen.",
        .status_no_such_domain = "Diese Domain existiert nicht (NXDOMAIN).",
        .status_failure = "Die Abfrage ist fehlgeschlagen (Zeitüberschreitung oder Serverfehler).",

        .settings_heading = "Einstellungen",
        .policy_label = "Richtlinie (p)",
        .policy_none = "Nur beobachten: Mails werden zugestellt, Berichte zeigen, wer in Ihrem Namen sendet.",
        .policy_quarantine = "Nicht bestandene Mails landen im Spam-Ordner.",
        .policy_reject = "Nicht bestandene Mails werden abgewiesen.",
        .subdomain_label = "Subdomains (sp)",
        .subdomain_like_domain = "Wie die Domain",
        .percentage_label = "Anteil der Mails (pct)",
        .rua_label = "Sammelberichte an (rua)",
        .rua_hint = "Tägliche Zusammenfassungen. Mehrere Adressen mit Komma trennen.",
        .ruf_label = "Fehlerberichte an (ruf)",
        .ruf_placeholder = "optional",
        .ruf_hint = "Einzelberichte pro Mail; nur wenige Anbieter senden sie.",
        .address_error = "Mindestens eine Adresse ist keine gültige E-Mail-Adresse.",
        .fo_label = "Fehlerbericht senden, wenn (fo)",
        .fo_all_fail = "SPF und DKIM schlagen fehl (0)",
        .fo_any_fails = "SPF oder DKIM schlägt fehl (1)",
        .fo_dkim_fails = "DKIM schlägt fehl (d)",
        .fo_spf_fails = "SPF schlägt fehl (s)",
        .adkim_label = "DKIM-Ausrichtung (adkim)",
        .aspf_label = "SPF-Ausrichtung (aspf)",
        .alignment_hint = "Relaxed: Subdomains der Absenderdomain zählen mit. Strict: nur exakt dieselbe Domain.",
        .record_heading = "DNS-Eintrag",
        .placeholder_domain_note = "Oben eine Domain eingeben; bis dahin steht example.com als Platzhalter.",
        .host_label = "Host / Name",
        .record_too_long = "Der Eintrag ist zu lang",
        .no_rua_title = "Ohne rua-Adresse erhalten Sie keine Berichte",
        .no_rua_description = "Ohne sie sehen Sie nicht, ob alle eigenen Dienste DMARC bestehen, bevor Sie die "
                              "Richtlinie verschärfen.",
        .foreign_reports_title = "Berichte gehen an eine fremde Domain",
        .published_heading = "Aktuell veröffentlicht",
        .not_looked_up = "Für diese Domain noch nicht abgefragt. „Abfragen“ zeigt den bestehenden Eintrag.",
        .no_dmarc_record = "Kein DMARC-Eintrag",
        .identical = "Identisch mit dem neuen Eintrag",
        .equivalent = "Gleiche Wirkung, nur anders geschrieben",
        .differs = "Weicht vom neuen Eintrag ab",

        .drop_title = "DMARC-Berichte hierher ziehen",
        .drop_description = ".zip, .gz oder .xml aus den Mails an die rua-Adresse, oder klicken zum Auswählen",
        .open_dialog_title = "DMARC-Bericht öffnen",
        .remove_all = "Alle entfernen",
        .reports_intro = "Die Berichte kommen als Mail-Anhang an die Adresse im rua-Tag des DMARC-Eintrags, meist "
                         "einmal täglich je Anbieter. Alles bleibt auf diesem Rechner.",
        .messages_reported = "Mails gemeldet",
        .dmarc_passed = "DMARC bestanden",
        .dmarc_failed = "Nicht bestanden",
        .reports_metric = "Berichte",
        .all_pass_title = "Alle gemeldeten Mails bestehen DMARC",
        .all_pass_description = "Sieht das über einige Wochen so aus, kann die Richtlinie auf p=reject.",
        .some_fail_title = "Einige Absender bestehen DMARC nicht",
        .some_fail_description = "Ist ein eigener Dienst darunter (Newsletter, Shop, CRM), fehlt dort DKIM oder SPF "
                                 "für die Domain. Unbekannte IPs sind meist Fälschungsversuche; die soll die "
                                 "Richtlinie abweisen.",
        .passed = "bestanden",
        .failed = "nicht bestanden",
        .no_signature = "keine Signatur",
        .column_sender_ip = "Absender-IP",
        .column_messages = "Mails",
        .column_spf = "SPF (Envelope-Domain)",
        .column_dkim = "DKIM (Domain, Selektor)",
        .column_disposition = "Behandlung",
        .error_cannot_open = "Die Datei lässt sich nicht öffnen.",
        .error_cannot_read = "Die Datei lässt sich nicht lesen.",
        .error_too_large = "Die Datei ist zu groß für einen Bericht.",
        .error_broken_archive = "Das Archiv ist beschädigt oder lässt sich nicht entpacken.",
        .error_not_xml = "Kein gültiges XML.",
        .error_not_a_report = "Kein DMARC-Bericht (kein <feedback>-Element).",
        .error_out_of_memory = "Zu wenig Speicher.",

        .date_format = "%d.%m.%Y",
    },
    .formats = {
        .mail_exchangers_one = "%d MX-Eintrag",
        .mail_exchangers_other = "%d MX-Einträge",
        .dkim_selectors = "Selektoren: %s",
        .dkim_missing = "Kein Selektor unter _domainkey veröffentlicht. Geprüft: %s.",
        .filter_all = "Alle (%d)",
        .source_direct = "Direkt beim Nameserver %s abgefragt, ohne Cache: Änderungen sind sofort sichtbar.",
        .failed_queries = "Keine Antwort für: %s",
        .loaded_from = "Vorbelegt mit dem Eintrag von %s",
        .foreign_reports = "Berichte an %s werden nur zugestellt, wenn dort der TXT-Eintrag %s mit dem Wert "
                           "\"v=DMARC1\" existiert.",
        .reports_loaded_one = "%d Bericht geladen",
        .reports_loaded_other = "%d Berichte geladen",
        .reports_already_loaded = ", %d schon vorhanden",
        .reports_unreadable = ", %d nicht lesbar (%s: %s)",
        .passing_share = "%ld (%.0f %%)",
    },
};

static const ui_text english = {
    .strings = {
        .domain_label = "Domain",
        .domain_error = "Please enter a valid domain.",
        .extra_names_label = "More names (optional)",
        .extra_names_hint = "Subdomains and DKIM selectors to look up as well.",
        .look_up_button = "Look Up",
        .page_records = "DNS Records",
        .page_dmarc = "Create DMARC",
        .page_reports = "DMARC Reports",

        .looking_up = "Looking up DNS …",
        .no_lookup_title = "No lookup yet",
        .no_lookup_description = "Enter a domain and press “Look Up”. The app asks for the domain's A, AAAA, CNAME, "
                                 "MX, NS, TXT, SOA and CAA records, plus www, common DKIM selectors (including "
                                 "Hetzner's default<YYMM>) and the extra names.",
        .present = "present",
        .missing = "missing",
        .name_unknown = "name unknown",
        .incoming_mail_card = "Incoming mail",
        .no_mail_exchanger = "No MX record found.",
        .no_spf = "No TXT record with v=spf1.",
        .no_dmarc = "No record under _dmarc. Create one in the “Create DMARC” tab.",
        .unknown_dkim_selectors = "There are selectors under _domainkey, but none of the names tried. Look up the "
                                  "selector at your mail provider and add it under “More names” as "
                                  "<selector>._domainkey.",
        .column_type = "Type",
        .column_name = "Name",
        .column_ttl = "TTL (s)",
        .column_value = "Value",
        .source_resolver = "No name server of the zone answered; asked the system resolver, which caches records "
                           "up to their TTL.",
        .some_queries_failed = "Not every query succeeded",
        .no_records_found = "No records found",
        .status_no_data = "The domain has no records of the types asked for.",
        .status_no_such_domain = "This domain does not exist (NXDOMAIN).",
        .status_failure = "The lookup failed (timeout or server error).",

        .settings_heading = "Settings",
        .policy_label = "Policy (p)",
        .policy_none = "Monitor only: mail is delivered, and reports show who sends in your name.",
        .policy_quarantine = "Failing mail goes to the spam folder.",
        .policy_reject = "Failing mail is rejected.",
        .subdomain_label = "Subdomains (sp)",
        .subdomain_like_domain = "Same as the domain",
        .percentage_label = "Share of mail (pct)",
        .rua_label = "Aggregate reports to (rua)",
        .rua_hint = "Daily summaries. Separate several addresses with commas.",
        .ruf_label = "Failure reports to (ruf)",
        .ruf_placeholder = "optional",
        .ruf_hint = "One report per message; few providers send them.",
        .address_error = "At least one address is not a valid email address.",
        .fo_label = "Send failure reports when (fo)",
        .fo_all_fail = "SPF and DKIM both fail (0)",
        .fo_any_fails = "SPF or DKIM fails (1)",
        .fo_dkim_fails = "DKIM fails (d)",
        .fo_spf_fails = "SPF fails (s)",
        .adkim_label = "DKIM alignment (adkim)",
        .aspf_label = "SPF alignment (aspf)",
        .alignment_hint = "Relaxed: subdomains of the sender's domain count too. Strict: only the exact same domain.",
        .record_heading = "DNS Record",
        .placeholder_domain_note = "Enter a domain above; until then example.com stands in.",
        .host_label = "Host / Name",
        .record_too_long = "The record is too long",
        .no_rua_title = "Without an rua address you get no reports",
        .no_rua_description = "Without them you cannot see whether all your own services pass DMARC before you "
                              "tighten the policy.",
        .foreign_reports_title = "Reports go to another domain",
        .published_heading = "Published now",
        .not_looked_up = "Not looked up for this domain yet. “Look Up” shows the existing record.",
        .no_dmarc_record = "No DMARC record",
        .identical = "Identical to the new record",
        .equivalent = "Same effect, written differently",
        .differs = "Differs from the new record",

        .drop_title = "Drop DMARC reports here",
        .drop_description = ".zip, .gz or .xml from the mail sent to the rua address, or click to choose",
        .open_dialog_title = "Open DMARC Report",
        .remove_all = "Remove All",
        .reports_intro = "Reports arrive as mail attachments at the address in the DMARC record's rua tag, usually "
                         "once a day per provider. Everything stays on this computer.",
        .messages_reported = "Messages reported",
        .dmarc_passed = "DMARC passed",
        .dmarc_failed = "Failed",
        .reports_metric = "Reports",
        .all_pass_title = "All reported mail passes DMARC",
        .all_pass_description = "If it stays this way for a few weeks, the policy can move to p=reject.",
        .some_fail_title = "Some senders fail DMARC",
        .some_fail_description = "If one of your own services is among them (newsletter, shop, CRM), it lacks DKIM "
                                 "or SPF for the domain. Unknown IPs are mostly spoofing; the policy should "
                                 "reject those.",
        .passed = "passed",
        .failed = "failed",
        .no_signature = "no signature",
        .column_sender_ip = "Sender IP",
        .column_messages = "Messages",
        .column_spf = "SPF (envelope domain)",
        .column_dkim = "DKIM (domain, selector)",
        .column_disposition = "Disposition",
        .error_cannot_open = "The file cannot be opened.",
        .error_cannot_read = "The file cannot be read.",
        .error_too_large = "The file is too large for a report.",
        .error_broken_archive = "The archive is damaged or does not unpack.",
        .error_not_xml = "Not valid XML.",
        .error_not_a_report = "Not a DMARC report (no <feedback> element).",
        .error_out_of_memory = "Out of memory.",

        .date_format = "%m/%d/%Y",
    },
    .formats = {
        .mail_exchangers_one = "%d MX record",
        .mail_exchangers_other = "%d MX records",
        .dkim_selectors = "Selectors: %s",
        .dkim_missing = "No selector published under _domainkey. Tried: %s.",
        .filter_all = "All (%d)",
        .source_direct = "Asked name server %s directly, without a cache: changes show right away.",
        .failed_queries = "No answer for: %s",
        .loaded_from = "Prefilled with the record of %s",
        .foreign_reports = "Reports to %s are only delivered if it publishes the TXT record %s with the value "
                           "\"v=DMARC1\".",
        .reports_loaded_one = "%d report loaded",
        .reports_loaded_other = "%d reports loaded",
        .reports_already_loaded = ", %d already loaded",
        .reports_unreadable = ", %d unreadable (%s: %s)",
        .passing_share = "%ld (%.0f%%)",
    },
};

const ui_text *ui_text_for(ui_language language) {
    return language == UI_LANGUAGE_GERMAN ? &german : &english;
}

static bool is_german_language_code(const char *code) {
    return code && strncmp(code, "de", 2) == 0;
}

#ifdef __APPLE__
/* The first language in System Settings, e.g. "de-DE"; apps started from
 * the Finder have no LANG variable to go by. */
static bool system_prefers_german(void) {
    CFArrayRef languages = CFLocaleCopyPreferredLanguages();
    bool prefers_german = false;
    if (languages && CFArrayGetCount(languages) > 0) {
        char code[16];
        CFStringRef first = CFArrayGetValueAtIndex(languages, 0);
        if (CFStringGetCString(first, code, sizeof code, kCFStringEncodingUTF8))
            prefers_german = is_german_language_code(code);
    }
    if (languages) CFRelease(languages);
    return prefers_german;
}
#else
static bool system_prefers_german(void) {
    const char *language = getenv("LC_ALL");
    if (!language || !*language) language = getenv("LC_MESSAGES");
    if (!language || !*language) language = getenv("LANG");
    return is_german_language_code(language);
}
#endif

ui_language ui_system_language(void) {
    return system_prefers_german() ? UI_LANGUAGE_GERMAN : UI_LANGUAGE_ENGLISH;
}

const char *ui_dns_status_message(const ui_text *text, dns_status status) {
    switch (status) {
    case DNS_STATUS_OK: return "";
    case DNS_STATUS_NO_DATA: return text->strings.status_no_data;
    case DNS_STATUS_NO_SUCH_DOMAIN: return text->strings.status_no_such_domain;
    case DNS_STATUS_FAILURE: return text->strings.status_failure;
    }
    return "";
}

const char *ui_report_error_message(const ui_text *text, report_error error) {
    switch (error) {
    case REPORT_ERROR_NONE: return "";
    case REPORT_ERROR_CANNOT_OPEN: return text->strings.error_cannot_open;
    case REPORT_ERROR_CANNOT_READ: return text->strings.error_cannot_read;
    case REPORT_ERROR_TOO_LARGE: return text->strings.error_too_large;
    case REPORT_ERROR_BROKEN_ARCHIVE: return text->strings.error_broken_archive;
    case REPORT_ERROR_NOT_XML: return text->strings.error_not_xml;
    case REPORT_ERROR_NOT_A_REPORT: return text->strings.error_not_a_report;
    case REPORT_ERROR_OUT_OF_MEMORY: return text->strings.error_out_of_memory;
    }
    return "";
}

const char *ui_plural(long count, const char *one, const char *other) {
    return count == 1 ? one : other;
}

void ui_format_day(const ui_text *text, long long seconds, char *out, size_t capacity) {
    time_t moment = (time_t)seconds;
    struct tm calendar;
    localtime_r(&moment, &calendar);
    strftime(out, capacity, text->strings.date_format, &calendar);
}
