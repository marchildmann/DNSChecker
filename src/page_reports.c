/* The DMARC reports page: aggregate reports dropped on the window or picked
 * in a file dialog, summed up per sender, failing senders first. */
#include "app_state.h"

#include <cui/cui_app.h>
#include <stdio.h>
#include <string.h>

static const char REPORT_EXTENSIONS[] = "zip;gz;xml";

/* ------------------------------------------------------------------------ */
/* Loading                                                                  */
/* ------------------------------------------------------------------------ */

static const char *file_name_of(const char *path) {
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static void load_one_file(dmarc_report_library *library, const char *path, report_load_summary *load) {
    report_error error;
    switch (dmarc_library_add_file(library, path, &error)) {
    case REPORT_ADDED: load->added++; break;
    case REPORT_ALREADY_LOADED: load->already_loaded++; break;
    case REPORT_UNREADABLE:
        if (load->unreadable++ == 0) {
            snprintf(load->first_unreadable_file, sizeof load->first_unreadable_file, "%s", file_name_of(path));
            load->first_error = error;
        }
        break;
    }
}

static void load_dropped_files(cui_ctx *ui, app_state *app, int file_count) {
    report_load_summary load = { .has_loaded = true };
    for (int i = 0; i < file_count; i++) load_one_file(&app->report_library, cui_dropped_file(ui, i), &load);
    app->last_report_load = load;
}

static void load_file_from_dialog(app_state *app, const ui_text *text) {
    char path[1024];
    cui_file_dialog_opts options = { .kind = CUI_FILE_OPEN, .title = text->strings.open_dialog_title,
                                     .filter_name = text->strings.page_reports, .filter = REPORT_EXTENSIONS };
    if (!cui_app_file_dialog(NULL, &options, path, sizeof path)) return;
    report_load_summary load = { .has_loaded = true };
    load_one_file(&app->report_library, path, &load);
    app->last_report_load = load;
}

/* The drop target; files dropped anywhere else on this page count too. */
static void report_drop_area(cui_ctx *ui, app_state *app, const ui_text *text) {
    bool has_reports = app->report_library.report_count > 0;
    int dropped = cui_dropzone(ui, "report-drop", .title = text->strings.drop_title,
                               .description = text->strings.drop_description, .icon = CUI_ICON_FILE_TEXT,
                               .accept = REPORT_EXTENSIONS, .compact = has_reports, .width = CUI_FILL);
    if (dropped < 0) load_file_from_dialog(app, text);
    int dropped_elsewhere = cui_dropped_file_count(ui);
    if (dropped > 0) load_dropped_files(ui, app, dropped);
    else if (dropped_elsewhere > 0) load_dropped_files(ui, app, dropped_elsewhere);
}

/* "3 reports loaded, 1 already loaded, 1 unreadable (x.zip: Not valid XML.)" */
static void describe_load(const report_load_summary *load, const ui_text *text, char *out, size_t capacity) {
    const ui_formats *formats = &text->formats;
    size_t used = 0;
    snprintf(out, capacity, ui_plural(load->added, formats->reports_loaded_one, formats->reports_loaded_other),
             load->added);
    used = strlen(out);
    if (load->already_loaded) snprintf(out + used, capacity - used, formats->reports_already_loaded, load->already_loaded);
    used = strlen(out);
    if (load->unreadable)
        snprintf(out + used, capacity - used, formats->reports_unreadable, load->unreadable,
                 load->first_unreadable_file, ui_report_error_message(text, load->first_error));
}

static void load_result(cui_ctx *ui, const report_load_summary *load, const ui_text *text) {
    char message[768];
    if (!load->has_loaded) return;
    describe_load(load, text, message, sizeof message);
    cui_alert(ui, message, .tone = load->unreadable ? CUI_TONE_WARNING : CUI_TONE_SUCCESS);
}

/* ------------------------------------------------------------------------ */
/* Overview                                                                 */
/* ------------------------------------------------------------------------ */

static void overview_metrics(cui_ctx *ui, const dmarc_report_library *library, const ui_text *text) {
    char reports[32], total[32], passing[48], failing[32], first_day[16], last_day[16], span[40];
    long failing_messages = library->total_messages - library->passing_messages;
    double passing_share = library->total_messages ? 100.0 * library->passing_messages / library->total_messages : 0;

    snprintf(reports, sizeof reports, "%d", library->report_count);
    snprintf(total, sizeof total, "%ld", library->total_messages);
    snprintf(passing, sizeof passing, text->formats.passing_share, library->passing_messages, passing_share);
    snprintf(failing, sizeof failing, "%ld", failing_messages);
    ui_format_day(text, library->first_time, first_day, sizeof first_day);
    ui_format_day(text, library->last_time, last_day, sizeof last_day);
    snprintf(span, sizeof span, "%s – %s", first_day, last_day);

    cui_box(ui, .dir = CUI_GRID, .columns = 4, .min_column_width = 200, .gap = 12, .width = CUI_FILL) {
        cui_metric(ui, text->strings.messages_reported, total, .icon = CUI_ICON_MAIL);
        cui_metric(ui, text->strings.dmarc_passed, passing, .icon = CUI_ICON_SHIELD);
        cui_metric(ui, text->strings.dmarc_failed, failing, .icon = CUI_ICON_CIRCLE_ALERT);
        cui_metric(ui, text->strings.reports_metric, reports, .icon = CUI_ICON_FILE_TEXT);
    }
    cui_muted(ui, span);
}

/* What the numbers mean for the next step, the reason to read reports at all. */
static void verdict(cui_ctx *ui, const dmarc_report_library *library, const ui_text *text) {
    bool has_failures = library->passing_messages < library->total_messages;
    if (!has_failures) {
        cui_alert(ui, text->strings.all_pass_title, .description = text->strings.all_pass_description,
                  .tone = CUI_TONE_SUCCESS);
        return;
    }
    cui_alert(ui, text->strings.some_fail_title, .description = text->strings.some_fail_description,
              .tone = CUI_TONE_WARNING);
}

/* ------------------------------------------------------------------------ */
/* Senders                                                                  */
/* ------------------------------------------------------------------------ */

static void result_badge(cui_ctx *ui, const char *check, bool has_passed) {
    cui_badge(ui, check, .tone = has_passed ? CUI_TONE_SUCCESS : CUI_TONE_DANGER, .dot = true);
}

static void describe_dkim(const dmarc_report_row *sender, const ui_text *text, char *out, size_t capacity) {
    if (sender->dkim_selector[0]) snprintf(out, capacity, "%s (%s)", sender->dkim_domain, sender->dkim_selector);
    else snprintf(out, capacity, "%s", sender->dkim_domain[0] ? sender->dkim_domain : text->strings.no_signature);
}

static void sender_row(cui_ctx *ui, const dmarc_report_row *sender, const ui_text *text) {
    char dkim_detail[REPORT_NAME_CAPACITY + REPORT_SHORT_CAPACITY + 4];
    describe_dkim(sender, text, dkim_detail, sizeof dkim_detail);
    bool passes = dmarc_row_passes(sender);

    cui_table_row(ui, false);
    cui_table_cell(ui);
    result_badge(ui, passes ? text->strings.passed : text->strings.failed, passes);
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

static void sender_table(cui_ctx *ui, const dmarc_report_library *library, const ui_text *text) {
    const cui_table_column columns[] = {
        { "DMARC", CUI_PX(150), CUI_TEXT_LEFT, false },
        { text->strings.column_sender_ip, CUI_PX(170), CUI_TEXT_LEFT, false },
        { text->strings.column_messages, CUI_PX(90), CUI_TEXT_RIGHT, false },
        { text->strings.column_spf, CUI_FILL, CUI_TEXT_LEFT, false },
        { text->strings.column_dkim, CUI_FILL, CUI_TEXT_LEFT, false },
        { text->strings.column_disposition, CUI_PX(110), CUI_TEXT_LEFT, false },
    };
    cui_table(ui, "senders", columns, 6, .striped = true) {
        for (int i = 0; i < library->sender_count; i++) {
            cui_push_id_int(ui, i);
            sender_row(ui, &library->senders[i], text);
            cui_pop_id(ui);
        }
    }
}

/* ------------------------------------------------------------------------ */
/* Page                                                                     */
/* ------------------------------------------------------------------------ */

static void loaded_reports_header(cui_ctx *ui, app_state *app, const ui_text *text) {
    cui_row(ui, .width = CUI_FILL, .gap = 12) {
        cui_column(ui, .width = CUI_FILL) { report_drop_area(ui, app, text); }
        if (cui_button(ui, text->strings.remove_all, .variant = CUI_BUTTON_OUTLINE, .icon = CUI_ICON_TRASH_2)) {
            dmarc_library_clear(&app->report_library);
            app->last_report_load = (report_load_summary){ 0 };
        }
    }
}

void reports_page(cui_ctx *ui, app_state *app) {
    const ui_text *text = app_text(app);
    const dmarc_report_library *library = &app->report_library;
    if (library->report_count == 0) report_drop_area(ui, app, text);
    else loaded_reports_header(ui, app, text);

    load_result(ui, &app->last_report_load, text);
    if (library->report_count == 0) {
        cui_muted(ui, text->strings.reports_intro);
        return;
    }
    overview_metrics(ui, library, text);
    verdict(ui, library, text);
    sender_table(ui, library, text);
}
