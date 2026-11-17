/* The "DMARC-Berichte" page: aggregate reports dropped on the window or
 * picked in a file dialog, summed up per sender, failing senders first. */
#include "app_state.h"

#include <cui/cui_app.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static const char REPORT_EXTENSIONS[] = "zip;gz;xml";

/* ------------------------------------------------------------------------ */
/* Loading                                                                  */
/* ------------------------------------------------------------------------ */

typedef struct load_tally {
    int added;
    int already_loaded;
    int unreadable;
    char first_problem[REPORT_ERROR_CAPACITY + 128];   /* "file.zip: reason" for the first failure */
} load_tally;

static const char *file_name_of(const char *path) {
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static void load_one_file(dmarc_report_library *library, const char *path, load_tally *tally) {
    char error[REPORT_ERROR_CAPACITY];
    switch (dmarc_library_add_file(library, path, error, sizeof error)) {
    case REPORT_ADDED: tally->added++; break;
    case REPORT_ALREADY_LOADED: tally->already_loaded++; break;
    case REPORT_UNREADABLE:
        if (tally->unreadable++ == 0)
            snprintf(tally->first_problem, sizeof tally->first_problem, "%s: %s", file_name_of(path), error);
        break;
    }
}

static void describe_load(const load_tally *tally, app_state *app) {
    char *message = app->report_load_message;
    size_t capacity = sizeof app->report_load_message;
    int used = snprintf(message, capacity, "%d Bericht%s geladen", tally->added, tally->added == 1 ? "" : "e");
    if (tally->already_loaded && used > 0 && (size_t)used < capacity)
        used += snprintf(message + used, capacity - (size_t)used, ", %d schon vorhanden", tally->already_loaded);
    if (tally->unreadable && used > 0 && (size_t)used < capacity)
        snprintf(message + used, capacity - (size_t)used, ", %d nicht lesbar (%s)", tally->unreadable, tally->first_problem);
    app->has_report_load_problem = tally->unreadable > 0;
}

static void load_dropped_files(cui_ctx *ui, app_state *app, int file_count) {
    load_tally tally = { 0 };
    for (int i = 0; i < file_count; i++) load_one_file(&app->report_library, cui_dropped_file(ui, i), &tally);
    describe_load(&tally, app);
}

static void load_file_from_dialog(app_state *app) {
    char path[1024];
    cui_file_dialog_opts options = { .kind = CUI_FILE_OPEN, .title = "DMARC-Bericht öffnen",
                                     .filter_name = "DMARC-Berichte", .filter = REPORT_EXTENSIONS };
    if (!cui_app_file_dialog(NULL, &options, path, sizeof path)) return;
    load_tally tally = { 0 };
    load_one_file(&app->report_library, path, &tally);
    describe_load(&tally, app);
}

/* The drop target; files dropped anywhere else on this page count too. */
static void report_drop_area(cui_ctx *ui, app_state *app) {
    bool has_reports = app->report_library.report_count > 0;
    int dropped = cui_dropzone(ui, "report-drop", .title = "DMARC-Berichte hierher ziehen",
                               .description = ".zip, .gz oder .xml aus den Mails an die rua-Adresse, oder klicken zum Auswählen",
                               .icon = CUI_ICON_FILE_TEXT, .accept = REPORT_EXTENSIONS, .compact = has_reports,
                               .width = CUI_FILL);
    if (dropped < 0) load_file_from_dialog(app);
    int dropped_elsewhere = cui_dropped_file_count(ui);
    if (dropped > 0) load_dropped_files(ui, app, dropped);
    else if (dropped_elsewhere > 0) load_dropped_files(ui, app, dropped_elsewhere);
}

/* ------------------------------------------------------------------------ */
/* Overview                                                                 */
/* ------------------------------------------------------------------------ */

static void format_day(long long seconds, char *out, size_t capacity) {
    time_t moment = (time_t)seconds;
    struct tm calendar;
    localtime_r(&moment, &calendar);
    strftime(out, capacity, "%d.%m.%Y", &calendar);
}

static void overview_metrics(cui_ctx *ui, const dmarc_report_library *library) {
    char reports[32], total[32], passing[48], failing[32], first_day[16], last_day[16], span[40];
    long failing_messages = library->total_messages - library->passing_messages;
    double passing_share = library->total_messages ? 100.0 * library->passing_messages / library->total_messages : 0;

    snprintf(reports, sizeof reports, "%d", library->report_count);
    snprintf(total, sizeof total, "%ld", library->total_messages);
    snprintf(passing, sizeof passing, "%ld (%.0f %%)", library->passing_messages, passing_share);
    snprintf(failing, sizeof failing, "%ld", failing_messages);
    format_day(library->first_time, first_day, sizeof first_day);
    format_day(library->last_time, last_day, sizeof last_day);
    snprintf(span, sizeof span, "%s – %s", first_day, last_day);

    cui_box(ui, .dir = CUI_GRID, .columns = 4, .min_column_width = 200, .gap = 12, .width = CUI_FILL) {
        cui_metric(ui, "Mails gemeldet", total, .icon = CUI_ICON_MAIL);
        cui_metric(ui, "DMARC bestanden", passing, .icon = CUI_ICON_SHIELD);
        cui_metric(ui, "Nicht bestanden", failing, .icon = CUI_ICON_CIRCLE_ALERT);
        cui_metric(ui, "Berichte", reports, .icon = CUI_ICON_FILE_TEXT);
    }
    cui_muted(ui, span);
}

/* What the numbers mean for the next step, the reason to read reports at all. */
static void verdict(cui_ctx *ui, const dmarc_report_library *library) {
    bool has_failures = library->passing_messages < library->total_messages;
    if (!has_failures) {
        cui_alert(ui, "Alle gemeldeten Mails bestehen DMARC",
                  .description = "Sieht das über einige Wochen so aus, kann die Richtlinie auf p=reject.",
                  .tone = CUI_TONE_SUCCESS);
        return;
    }
    cui_alert(ui, "Einige Absender bestehen DMARC nicht",
              .description = "Ist ein eigener Dienst darunter (Newsletter, Shop, CRM), fehlt dort DKIM oder SPF für die "
                             "Domain. Unbekannte IPs sind meist Fälschungsversuche; die soll die Richtlinie abweisen.",
              .tone = CUI_TONE_WARNING);
}

/* ------------------------------------------------------------------------ */
/* Senders                                                                  */
/* ------------------------------------------------------------------------ */

static void result_badge(cui_ctx *ui, const char *check, bool has_passed) {
    cui_badge(ui, check, .tone = has_passed ? CUI_TONE_SUCCESS : CUI_TONE_DANGER, .dot = true);
}

static void sender_row(cui_ctx *ui, const dmarc_report_row *sender) {
    char dkim_detail[REPORT_NAME_CAPACITY + REPORT_SHORT_CAPACITY + 4];
    if (sender->dkim_selector[0])
        snprintf(dkim_detail, sizeof dkim_detail, "%s (%s)", sender->dkim_domain, sender->dkim_selector);
    else
        snprintf(dkim_detail, sizeof dkim_detail, "%s", sender->dkim_domain[0] ? sender->dkim_domain : "keine Signatur");

    cui_table_row(ui, false);
    cui_table_cell(ui);
    result_badge(ui, dmarc_row_passes(sender) ? "bestanden" : "nicht bestanden", dmarc_row_passes(sender));
    cui_table_cell(ui);
    cui_text(ui, sender->source_ip, .font = CUI_FONT_MONO, .size = 12, .nowrap = true);
    cui_table_cell_textf(ui, "%ld", sender->message_count);
    cui_table_cell(ui);
    cui_column(ui, .gap = 4) {
        result_badge(ui, "SPF", sender->spf_passed);
        cui_text(ui, sender->spf_domain, .size = 12, .color = CUI_COLOR_TEXT_SECONDARY);
    }
    cui_table_cell(ui);
    cui_column(ui, .gap = 4) {
        result_badge(ui, "DKIM", sender->dkim_passed);
        cui_text(ui, dkim_detail, .size = 12, .color = CUI_COLOR_TEXT_SECONDARY);
    }
    cui_table_cell_text(ui, sender->disposition);
}

static void sender_table(cui_ctx *ui, const dmarc_report_library *library) {
    static const cui_table_column columns[] = {
        { "DMARC", CUI_PX(150), CUI_TEXT_LEFT, false },
        { "Absender-IP", CUI_PX(170), CUI_TEXT_LEFT, false },
        { "Mails", CUI_PX(70), CUI_TEXT_RIGHT, false },
        { "SPF (Envelope-Domain)", CUI_FILL, CUI_TEXT_LEFT, false },
        { "DKIM (Domain, Selektor)", CUI_FILL, CUI_TEXT_LEFT, false },
        { "Behandlung", CUI_PX(110), CUI_TEXT_LEFT, false },
    };
    cui_table(ui, "senders", columns, 6, .striped = true) {
        for (int i = 0; i < library->sender_count; i++) {
            cui_push_id_int(ui, i);
            sender_row(ui, &library->senders[i]);
            cui_pop_id(ui);
        }
    }
}

/* ------------------------------------------------------------------------ */
/* Page                                                                     */
/* ------------------------------------------------------------------------ */

static void loaded_reports_header(cui_ctx *ui, app_state *app) {
    cui_row(ui, .width = CUI_FILL, .gap = 12) {
        cui_column(ui, .width = CUI_FILL) { report_drop_area(ui, app); }
        if (cui_button(ui, "Alle entfernen", .variant = CUI_BUTTON_OUTLINE, .icon = CUI_ICON_TRASH_2)) {
            dmarc_library_clear(&app->report_library);
            app->report_load_message[0] = '\0';
        }
    }
}

void reports_page(cui_ctx *ui, app_state *app) {
    const dmarc_report_library *library = &app->report_library;
    if (library->report_count == 0) report_drop_area(ui, app);
    else loaded_reports_header(ui, app);

    if (app->report_load_message[0])
        cui_alert(ui, app->report_load_message, .tone = app->has_report_load_problem ? CUI_TONE_WARNING : CUI_TONE_SUCCESS);
    if (library->report_count == 0) {
        cui_muted(ui, "Die Berichte kommen als Mail-Anhang an die Adresse im rua-Tag des DMARC-Eintrags, meist einmal "
                      "täglich je Anbieter. Alles bleibt auf diesem Rechner.");
        return;
    }
    overview_metrics(ui, library);
    verdict(ui, library);
    sender_table(ui, library);
}
