/* The Create DMARC page: a form on the left, and on the right the record it
 * makes, ready to copy, next to what the domain publishes today. */
#include "app_state.h"

#include <stdio.h>
#include <string.h>

enum { SUBDOMAIN_POLICY_LIKE_DOMAIN = 0 };

static dmarc_settings dmarc_settings_from_form(const dmarc_form *form) {
    bool has_subdomain_policy = form->subdomain_policy_index != SUBDOMAIN_POLICY_LIKE_DOMAIN;
    dmarc_settings settings = {
        .policy = (dmarc_policy)form->policy_index,
        .has_subdomain_policy = has_subdomain_policy,
        .subdomain_policy = has_subdomain_policy ? (dmarc_policy)(form->subdomain_policy_index - 1) : DMARC_POLICY_NONE,
        .percentage = (int)form->percentage,
        .failure_reporting = (dmarc_failure_reporting)form->failure_reporting_index,
        .dkim_alignment = (dmarc_alignment)form->dkim_alignment_index,
        .spf_alignment = (dmarc_alignment)form->spf_alignment_index,
    };
    snprintf(settings.aggregate_report_addresses, sizeof settings.aggregate_report_addresses, "%s", form->aggregate_addresses);
    snprintf(settings.failure_report_addresses, sizeof settings.failure_report_addresses, "%s", form->failure_addresses);
    return settings;
}

static void dmarc_form_from_settings(const dmarc_settings *settings, dmarc_form *form) {
    *form = (dmarc_form){
        .policy_index = (int)settings->policy,
        .subdomain_policy_index = settings->has_subdomain_policy ? (int)settings->subdomain_policy + 1
                                                                  : SUBDOMAIN_POLICY_LIKE_DOMAIN,
        .percentage = settings->percentage,
        .failure_reporting_index = (int)settings->failure_reporting,
        .dkim_alignment_index = (int)settings->dkim_alignment,
        .spf_alignment_index = (int)settings->spf_alignment,
    };
    snprintf(form->aggregate_addresses, sizeof form->aggregate_addresses, "%s", settings->aggregate_report_addresses);
    snprintf(form->failure_addresses, sizeof form->failure_addresses, "%s", settings->failure_report_addresses);
}

void dmarc_form_reset(dmarc_form *form) {
    dmarc_form_from_settings(&(dmarc_settings){ .policy = DMARC_POLICY_NONE, .percentage = 100 }, form);
}

/* A domain that already publishes DMARC starts from its record, so editing
 * it cannot silently weaken the policy; any other starts from the defaults. */
bool dmarc_form_load_published(dmarc_form *form, const mail_security_summary *mail) {
    dmarc_settings published;
    bool has_published_record = mail->has_dmarc && dmarc_parse_record(mail->dmarc_record, &published);
    if (has_published_record) dmarc_form_from_settings(&published, form);
    else dmarc_form_reset(form);
    return has_published_record;
}

/* ------------------------------------------------------------------------ */
/* Form                                                                     */
/* ------------------------------------------------------------------------ */

static const char *policy_explanation(int policy_index, const ui_text *text) {
    switch (policy_index) {
    case DMARC_POLICY_QUARANTINE: return text->strings.policy_quarantine;
    case DMARC_POLICY_REJECT: return text->strings.policy_reject;
    default: return text->strings.policy_none;
    }
}

static void policy_fields(cui_ctx *ui, dmarc_form *form, const ui_text *text) {
    static const char *const policies[] = { "none", "quarantine", "reject" };
    const char *const subdomain_policies[] = { text->strings.subdomain_like_domain, "none", "quarantine", "reject" };

    cui_label(ui, text->strings.policy_label);
    cui_segmented(ui, "policy", policies, 3, &form->policy_index, .full_width = true);
    cui_muted(ui, policy_explanation(form->policy_index, text));
    cui_select(ui, "subdomain-policy", subdomain_policies, 4, &form->subdomain_policy_index,
               .label = text->strings.subdomain_label, .width = CUI_FILL);
    cui_number(ui, "percentage", &form->percentage, 0, 100, .label = text->strings.percentage_label, .step = 10,
               .suffix = "%", .width = CUI_FILL);
}

static const char *address_error(const char *addresses, const ui_text *text) {
    return dmarc_address_list_is_valid(addresses) ? NULL : text->strings.address_error;
}

static void report_fields(cui_ctx *ui, dmarc_form *form, const ui_text *text) {
    const char *const failure_reporting[] = {
        text->strings.fo_all_fail, text->strings.fo_any_fails, text->strings.fo_dkim_fails, text->strings.fo_spf_fails,
    };
    bool has_failure_addresses = form->failure_addresses[0] != '\0';

    cui_input(ui, "rua", form->aggregate_addresses, sizeof form->aggregate_addresses,
              .label = text->strings.rua_label, .placeholder = "dmarc@example.com", .icon = CUI_ICON_MAIL,
              .hint = text->strings.rua_hint, .error = address_error(form->aggregate_addresses, text));
    cui_input(ui, "ruf", form->failure_addresses, sizeof form->failure_addresses,
              .label = text->strings.ruf_label, .placeholder = text->strings.ruf_placeholder, .icon = CUI_ICON_MAIL,
              .hint = text->strings.ruf_hint, .error = address_error(form->failure_addresses, text));
    cui_select(ui, "fo", failure_reporting, 4, &form->failure_reporting_index, .label = text->strings.fo_label,
               .disabled = !has_failure_addresses, .width = CUI_FILL);
}

static void alignment_fields(cui_ctx *ui, dmarc_form *form, const ui_text *text) {
    static const char *const alignments[] = { "Relaxed", "Strict" };
    cui_row(ui, .width = CUI_FILL, .gap = 16) {
        cui_column(ui, .width = CUI_FILL, .gap = 6) {
            cui_label(ui, text->strings.adkim_label);
            cui_segmented(ui, "adkim", alignments, 2, &form->dkim_alignment_index, .full_width = true);
        }
        cui_column(ui, .width = CUI_FILL, .gap = 6) {
            cui_label(ui, text->strings.aspf_label);
            cui_segmented(ui, "aspf", alignments, 2, &form->spf_alignment_index, .full_width = true);
        }
    }
    cui_muted(ui, text->strings.alignment_hint);
}

/* `loaded_from_domain` names the domain whose published record filled the
 * form, or is NULL when the form started from the defaults. */
static void form_card(cui_ctx *ui, dmarc_form *form, const char *loaded_from_domain, const ui_text *text) {
    char loaded_note[DNS_DOMAIN_CAPACITY + 64];
    cui_card(ui, .width = CUI_FILL, .gap = 12, .pad = 20) {
        cui_heading(ui, text->strings.settings_heading, 4);
        if (loaded_from_domain) {
            snprintf(loaded_note, sizeof loaded_note, text->formats.loaded_from, loaded_from_domain);
            cui_badge(ui, loaded_note, .tone = CUI_TONE_INFO, .icon = CUI_ICON_REFRESH_CW);
        }
        policy_fields(ui, form, text);
        cui_separator(ui);
        report_fields(ui, form, text);
        cui_separator(ui);
        alignment_fields(ui, form, text);
    }
}

/* ------------------------------------------------------------------------ */
/* Result                                                                   */
/* ------------------------------------------------------------------------ */

static void copyable_field(cui_ctx *ui, const char *id, const char *label, const char *value) {
    cui_column(ui, .width = CUI_FILL, .gap = 4) {
        cui_muted(ui, label);
        cui_row(ui, .width = CUI_FILL, .gap = 8) {
            cui_text(ui, value, .font = CUI_FONT_MONO, .width = CUI_FILL);
            cui_copy_button(ui, id, value);
        }
    }
}

/* Hints for mistakes that keep a record from working the way it reads. */
static void record_hints(cui_ctx *ui, const char *domain, const dmarc_form *form, const ui_text *text) {
    char foreign_domain[DNS_DOMAIN_CAPACITY], authorization_host[DNS_DOMAIN_CAPACITY * 2 + 32], description[1024];

    if (!form->aggregate_addresses[0])
        cui_alert(ui, text->strings.no_rua_title, .description = text->strings.no_rua_description,
                  .tone = CUI_TONE_WARNING);

    bool reports_go_elsewhere =
        dmarc_find_foreign_report_domain(domain, form->aggregate_addresses, foreign_domain, sizeof foreign_domain) ||
        dmarc_find_foreign_report_domain(domain, form->failure_addresses, foreign_domain, sizeof foreign_domain);
    if (!domain[0] || !reports_go_elsewhere) return;

    snprintf(authorization_host, sizeof authorization_host, "%s._report._dmarc.%s", domain, foreign_domain);
    snprintf(description, sizeof description, text->formats.foreign_reports, foreign_domain, authorization_host);
    cui_alert(ui, text->strings.foreign_reports_title, .description = description, .tone = CUI_TONE_INFO);
}

static const char *comparison_with_published(const char *published, const char *generated, const ui_text *text,
                                             bool *is_equivalent) {
    bool is_identical = strcmp(published, generated) == 0;
    *is_equivalent = is_identical || dmarc_records_are_equivalent(published, generated);
    if (is_identical) return text->strings.identical;
    return *is_equivalent ? text->strings.equivalent : text->strings.differs;
}

/* What the domain publishes today, from the last lookup of this domain. */
static void published_record(cui_ctx *ui, const lookup_report *report, const char *domain, const char *generated,
                             const ui_text *text) {
    bool has_lookup_of_domain = report && domain[0] && strcmp(report->domain, domain) == 0;
    cui_separator(ui);
    cui_label(ui, text->strings.published_heading);
    if (!has_lookup_of_domain) {
        cui_muted(ui, text->strings.not_looked_up);
        return;
    }
    if (!report->mail.has_dmarc) {
        cui_badge(ui, text->strings.no_dmarc_record, .tone = CUI_TONE_WARNING, .dot = true);
        return;
    }
    bool is_equivalent;
    const char *comparison = comparison_with_published(report->mail.dmarc_record, generated, text, &is_equivalent);
    cui_badge(ui, comparison, .tone = is_equivalent ? CUI_TONE_SUCCESS : CUI_TONE_INFO, .dot = true);
    cui_text(ui, report->mail.dmarc_record, .font = CUI_FONT_MONO, .size = 12, .color = CUI_COLOR_TEXT_SECONDARY);
}

static void result_card(cui_ctx *ui, const app_state *app, const char *domain, const ui_text *text) {
    char record[DMARC_RECORD_CAPACITY], host[DNS_DOMAIN_CAPACITY + 8];
    dmarc_settings settings = dmarc_settings_from_form(&app->dmarc);
    bool fits = dmarc_build_record(&settings, record, sizeof record);
    dmarc_record_host(domain, host, sizeof host);

    cui_card(ui, .width = CUI_FILL, .gap = 14, .pad = 20) {
        cui_heading(ui, text->strings.record_heading, 4);
        if (!domain[0]) cui_muted(ui, text->strings.placeholder_domain_note);
        copyable_field(ui, "copy-host", text->strings.host_label, host);
        copyable_field(ui, "copy-type", text->strings.column_type, "TXT");
        if (fits) copyable_field(ui, "copy-value", text->strings.column_value, record);
        else cui_alert(ui, text->strings.record_too_long, .tone = CUI_TONE_DANGER);
        record_hints(ui, domain, &app->dmarc, text);
        published_record(ui, app->report, domain, record, text);
    }
}

/* ------------------------------------------------------------------------ */
/* Page                                                                     */
/* ------------------------------------------------------------------------ */

void dmarc_page(cui_ctx *ui, app_state *app) {
    const ui_text *text = app_text(app);
    char domain[DNS_DOMAIN_CAPACITY];
    app_current_domain(app, domain, sizeof domain);

    bool is_form_from_this_domain = app->is_dmarc_form_from_published && app->report &&
                                    strcmp(app->report->domain, domain) == 0;
    const char *loaded_from_domain = is_form_from_this_domain ? app->report->domain : NULL;

    cui_row(ui, .width = CUI_FILL, .gap = 16, .align = CUI_ALIGN_START) {
        cui_column(ui, .width = CUI_GROW(1), .min_width = 320) { form_card(ui, &app->dmarc, loaded_from_domain, text); }
        cui_column(ui, .width = CUI_GROW(1), .min_width = 320) { result_card(ui, app, domain, text); }
    }
}
