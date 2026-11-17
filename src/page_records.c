/* The "DNS-Einträge" page: the mail authentication summary and a table of
 * every record found, filtered by type. */
#include "app_state.h"

#include <stdio.h>
#include <string.h>

enum { FILTER_ALL_TYPES = 0, MAX_FILTER_LABELS = 16, FILTER_LABEL_CAPACITY = 24 };

static void waiting_state(cui_ctx *ui) {
    cui_row(ui, .gap = 10, .pad_y = 24) {
        cui_spinner(ui, 18);
        cui_secondary(ui, "DNS wird abgefragt …");
    }
}

/* ------------------------------------------------------------------------ */
/* Mail authentication summary                                              */
/* ------------------------------------------------------------------------ */

static void summary_card(cui_ctx *ui, const char *title, bool is_present, const char *status, const char *detail) {
    cui_card(ui, .width = CUI_FILL, .gap = 8, .pad = 16) {
        cui_row(ui, .width = CUI_FILL, .gap = 8) {
            cui_label(ui, title);
            cui_spacer(ui);
            cui_badge(ui, status, .tone = is_present ? CUI_TONE_SUCCESS : CUI_TONE_WARNING, .dot = true);
        }
        cui_text(ui, detail, .font = CUI_FONT_MONO, .size = 12, .color = CUI_COLOR_TEXT_SECONDARY);
    }
}

static void dkim_card(cui_ctx *ui, const mail_security_summary *mail) {
    char checked[512], detail[1024];
    if (mail->dkim_selector_count > 0) {
        snprintf(detail, sizeof detail, "Selektoren: %s", mail->dkim_selectors);
        summary_card(ui, "DKIM", true, "vorhanden", detail);
        return;
    }
    if (mail->has_unknown_dkim_selectors) {
        summary_card(ui, "DKIM", false, "Name unbekannt",
                     "Unter _domainkey gibt es Selektoren, aber keiner der geprüften Namen. Den Selektor beim "
                     "Mail-Anbieter nachsehen und unter „Weitere Namen“ als <selektor>._domainkey eintragen.");
        return;
    }
    checked[0] = '\0';
    for (int i = 0; i < scan_common_dkim_selector_count; i++) {
        size_t used = strlen(checked);
        snprintf(checked + used, sizeof checked - used, "%s%s", i ? ", " : "", scan_common_dkim_selectors[i]);
    }
    snprintf(detail, sizeof detail, "Kein Selektor unter _domainkey veröffentlicht. Geprüft: %s.", checked);
    summary_card(ui, "DKIM", false, "fehlt", detail);
}

static void mail_summary(cui_ctx *ui, const mail_security_summary *mail) {
    char mail_exchangers[64];
    snprintf(mail_exchangers, sizeof mail_exchangers, "%d MX-Eintr%s", mail->mail_exchanger_count,
             mail->mail_exchanger_count == 1 ? "ag" : "äge");
    bool has_mail_exchangers = mail->mail_exchanger_count > 0;

    cui_box(ui, .dir = CUI_GRID, .columns = 4, .min_column_width = 220, .gap = 12, .width = CUI_FILL) {
        summary_card(ui, "E-Mail-Empfang", has_mail_exchangers, has_mail_exchangers ? "vorhanden" : "fehlt",
                     has_mail_exchangers ? mail_exchangers : "Kein MX-Eintrag gefunden.");
        summary_card(ui, "SPF", mail->has_spf, mail->has_spf ? "vorhanden" : "fehlt",
                     mail->has_spf ? mail->spf_record : "Kein TXT-Eintrag mit v=spf1.");
        dkim_card(ui, mail);
        summary_card(ui, "DMARC", mail->has_dmarc, mail->has_dmarc ? "vorhanden" : "fehlt",
                     mail->has_dmarc ? mail->dmarc_record : "Kein Eintrag unter _dmarc. Im Tab „DMARC erstellen“ anlegen.");
    }
}

/* ------------------------------------------------------------------------ */
/* Record table                                                             */
/* ------------------------------------------------------------------------ */

typedef struct record_filter {
    char labels[MAX_FILTER_LABELS][FILTER_LABEL_CAPACITY];
    const char *label_pointers[MAX_FILTER_LABELS];
    int count;
} record_filter;

static int count_records_of_type(const dns_record_list *records, const char *type) {
    int count = 0;
    for (int i = 0; i < records->count; i++)
        if (strcmp(records->records[i].type, type) == 0) count++;
    return count;
}

/* "Alle (12)", "A (2)", "MX (1)", ...: the counts tell what is there before a click. */
static void build_record_filter(const dns_record_list *records, record_filter *filter) {
    filter->count = 0;
    snprintf(filter->labels[filter->count++], FILTER_LABEL_CAPACITY, "Alle (%d)", records->count);
    for (int i = 0; i < dns_record_type_count; i++) {
        const char *type = dns_record_types[i].label;
        snprintf(filter->labels[filter->count++], FILTER_LABEL_CAPACITY, "%s (%d)", type,
                 count_records_of_type(records, type));
    }
    for (int i = 0; i < filter->count; i++) filter->label_pointers[i] = filter->labels[i];
}

static bool is_shown_by_filter(const dns_record *record, int filter_index) {
    if (filter_index == FILTER_ALL_TYPES) return true;
    return strcmp(record->type, dns_record_types[filter_index - 1].label) == 0;
}

static void record_row(cui_ctx *ui, const dns_record *record, const char *domain) {
    char shown_name[DNS_DOMAIN_CAPACITY];
    dns_relative_name(record->name, domain, shown_name, sizeof shown_name);

    cui_table_row(ui, false);
    cui_table_cell(ui);
    cui_badge(ui, record->type, .tone = CUI_TONE_ACCENT);
    cui_table_cell(ui);
    cui_text(ui, shown_name, .nowrap = true);
    cui_table_cell_textf(ui, "%lu", record->ttl_seconds);
    cui_table_cell(ui);
    cui_text(ui, record->value, .font = CUI_FONT_MONO, .size = 12, .width = CUI_FILL);
}

static void record_table(cui_ctx *ui, const lookup_report *report, int filter_index) {
    const dns_record_list *records = &report->records;
    static const cui_table_column columns[] = {
        { "Typ", CUI_PX(90), CUI_TEXT_LEFT, false },
        { "Name", CUI_PX(220), CUI_TEXT_LEFT, false },
        { "TTL (s)", CUI_PX(80), CUI_TEXT_RIGHT, false },
        { "Wert", CUI_FILL, CUI_TEXT_LEFT, false },
    };
    cui_table(ui, "records", columns, 4, .compact = true, .striped = true) {
        for (int i = 0; i < records->count; i++) {
            if (!is_shown_by_filter(&records->records[i], filter_index)) continue;
            cui_push_id_int(ui, i);
            record_row(ui, &records->records[i], report->domain);
            cui_pop_id(ui);
        }
    }
}

static void record_section(cui_ctx *ui, app_state *app) {
    record_filter filter;
    build_record_filter(&app->report->records, &filter);
    cui_tabs(ui, "record-filter", filter.label_pointers, filter.count, &app->record_filter_index,
             .variant = CUI_TABS_PILL);
    record_table(ui, app->report, app->record_filter_index);
}

/* ------------------------------------------------------------------------ */
/* Page                                                                     */
/* ------------------------------------------------------------------------ */

/* Says where the answers came from, since a cache can lag behind a change. */
static void source_note(cui_ctx *ui, const lookup_report *report) {
    char note[DNS_DOMAIN_CAPACITY + 96];
    if (report->asks_name_server_directly)
        snprintf(note, sizeof note, "Direkt beim Nameserver %s abgefragt, ohne Cache: Änderungen sind sofort sichtbar.",
                 report->name_server.host_name);
    else
        snprintf(note, sizeof note, "Kein Nameserver der Zone erreichbar; abgefragt über den Systemresolver, "
                                    "der Einträge bis zu ihrer TTL zwischenspeichert.");
    cui_muted(ui, note);
}

static void report_problem(cui_ctx *ui, const lookup_report *report) {
    bool found_some_records = report->records.count > 0;
    cui_alert(ui, found_some_records ? "Nicht alle Abfragen waren erfolgreich" : "Keine Einträge gefunden",
              .description = report->problem, .tone = found_some_records ? CUI_TONE_WARNING : CUI_TONE_DANGER);
}

void records_page(cui_ctx *ui, app_state *app) {
    if (lookup_task_is_running(&app->lookup)) {
        waiting_state(ui);
        return;
    }
    if (!app->report) {
        cui_empty_state(ui, "Noch keine Abfrage", .icon = CUI_ICON_GLOBE,
                        .description = "Domain eingeben und „Abfragen“ drücken. Abgefragt werden A, AAAA, CNAME, MX, NS, TXT, SOA "
                                       "und CAA der Domain, dazu www, gängige DKIM-Selektoren (auch Hetzners default<JJMM>) "
                                       "und die weiteren Namen.");
        return;
    }

    cui_heading(ui, app->report->domain, 4);
    source_note(ui, app->report);
    if (app->report->problem[0]) report_problem(ui, app->report);
    if (app->report->records.count == 0) return;
    mail_summary(ui, &app->report->mail);
    record_section(ui, app);
}
