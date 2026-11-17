/* DNS Checker: looks up a domain's DNS records and builds DMARC records.
 * This file holds the window, the domain field and the page switch; the
 * pages live in page_records.c, page_dmarc.c and page_reports.c. */
#include "app_state.h"

#include <cui/cui_app.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { PAGE_RECORDS = 0, PAGE_DMARC, PAGE_REPORTS, PAGE_COUNT };

void app_current_domain(const app_state *app, char *out, size_t capacity) {
    if (!dns_normalize_domain(app->domain_input, out, capacity)) out[0] = '\0';
}

static void start_lookup(app_state *app) {
    char domain[DNS_DOMAIN_CAPACITY];
    app->was_lookup_attempted = true;
    app_current_domain(app, domain, sizeof domain);
    if (domain[0]) lookup_task_start(&app->lookup, domain, app->extra_names_input);
}

static void append_extra_name(app_state *app, const char *name) {
    size_t used = strlen(app->extra_names_input);
    snprintf(app->extra_names_input + used, sizeof app->extra_names_input - used, "%s%s", used ? ", " : "", name);
}

static void collect_finished_lookup(app_state *app) {
    lookup_report *finished = lookup_task_take_report(&app->lookup);
    if (!finished) return;
    free(app->report);
    app->report = finished;
    app->record_filter_index = 0;
    app->is_dmarc_form_from_published = dmarc_form_load_published(&app->dmarc, &finished->mail);
}

const ui_text *app_text(const app_state *app) {
    return ui_text_for((ui_language)app->language);
}

static void domain_bar(cui_ctx *ui, app_state *app, const ui_text *text) {
    char domain[DNS_DOMAIN_CAPACITY];
    app_current_domain(app, domain, sizeof domain);
    bool is_running = lookup_task_is_running(&app->lookup);
    bool shows_error = app->was_lookup_attempted && !domain[0];
    int domain_events = 0, extra_names_events = 0;
    bool wants_lookup = false;

    cui_row(ui, .width = CUI_FILL, .gap = 12, .align = CUI_ALIGN_START) {
        domain_events = cui_input(ui, "domain", app->domain_input, sizeof app->domain_input,
                                  .label = text->strings.domain_label, .placeholder = "example.com",
                                  .icon = CUI_ICON_GLOBE, .autofocus = true, .width = CUI_GROW(2),
                                  .error = shows_error ? text->strings.domain_error : NULL);
        extra_names_events = cui_input(ui, "extra-names", app->extra_names_input, sizeof app->extra_names_input,
                                       .label = text->strings.extra_names_label, .placeholder = "lp, shop, xyz._domainkey",
                                       .icon = CUI_ICON_LIST, .width = CUI_GROW(3), .hint = text->strings.extra_names_hint);
        cui_column(ui, .pad_top = 24) {   /* level with the fields, below their labels */
            wants_lookup = cui_button(ui, text->strings.look_up_button, .variant = CUI_BUTTON_PRIMARY,
                                      .icon = CUI_ICON_SEARCH, .loading = is_running);
        }
    }
    bool was_submitted = (domain_events | extra_names_events) & CUI_SUBMITTED;
    if ((wants_lookup || was_submitted) && !is_running) start_lookup(app);
}

static void title_bar(cui_ctx *ui, app_state *app) {
    static const char *const languages[UI_LANGUAGE_COUNT] = { "DE", "EN" };
    cui_row(ui, .width = CUI_FILL, .gap = 10) {
        cui_icon(ui, CUI_ICON_SERVER, 22, CUI_COLOR_ACCENT);
        cui_heading(ui, "DNS Checker", 3);
        cui_spacer(ui);
        cui_segmented(ui, "language", languages, UI_LANGUAGE_COUNT, &app->language, .size = CUI_SIZE_SM);
    }
}

static void frame(cui_ctx *ui, void *user) {
    app_state *app = user;
    const ui_text *text = app_text(app);
    const char *const page_titles[PAGE_COUNT] = {
        text->strings.page_records, text->strings.page_dmarc, text->strings.page_reports,
    };
    static const char *const page_icons[PAGE_COUNT] = { CUI_ICON_LIST, CUI_ICON_SHIELD, CUI_ICON_FILE_TEXT };

    collect_finished_lookup(app);

    cui_column(ui, .width = CUI_FILL, .height = CUI_FILL, .bg = CUI_COLOR_BACKGROUND, .pad = 24, .gap = 16) {
        title_bar(ui, app);
        domain_bar(ui, app, text);
        cui_tabs(ui, "pages", page_titles, PAGE_COUNT, &app->active_page, .icons = page_icons);
        cui_scroll(ui, .id = "page", .width = CUI_FILL, .height = CUI_FILL, .gap = 16) {
            switch (app->active_page) {
            case PAGE_RECORDS: records_page(ui, app); break;
            case PAGE_DMARC: dmarc_page(ui, app); break;
            default: reports_page(ui, app); break;
            }
        }
    }

    /* the worker cannot wake the window, so look for its report while it runs */
    if (lookup_task_is_running(&app->lookup)) cui_request_wakeup(ui, 0.1f);
}

/* `dns_checker example.com [names...]` opens with that domain already looked
 * up, the further arguments being the extra names. */
int main(int argc, char **argv) {
    static app_state app;
    app.language = ui_system_language();
    dmarc_form_reset(&app.dmarc);
    lookup_task_init(&app.lookup);
    if (argc > 1) {
        snprintf(app.domain_input, sizeof app.domain_input, "%s", argv[1]);
        for (int i = 2; i < argc; i++) append_extra_name(&app, argv[i]);
        start_lookup(&app);
    }
    return cui_app_run(&(cui_app_desc){ .title = "DNS Checker", .width = 1100, .height = 760,
                                        .min_width = 720, .min_height = 520, .follow_system_theme = true },
                       frame, &app);
}
