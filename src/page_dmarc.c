/* The "DMARC erstellen" page: a form on the left, and on the right the
 * record it makes, ready to copy, next to what the domain publishes today. */
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

static const char *policy_explanation(int policy_index) {
    switch (policy_index) {
    case DMARC_POLICY_QUARANTINE: return "Nicht bestandene Mails landen im Spam-Ordner.";
    case DMARC_POLICY_REJECT: return "Nicht bestandene Mails werden abgewiesen.";
    default: return "Nur beobachten: Mails werden zugestellt, Berichte zeigen, wer in Ihrem Namen sendet.";
    }
}

static void policy_fields(cui_ctx *ui, dmarc_form *form) {
    static const char *const policies[] = { "none", "quarantine", "reject" };
    static const char *const subdomain_policies[] = { "Wie die Domain", "none", "quarantine", "reject" };

    cui_label(ui, "Richtlinie (p)");
    cui_segmented(ui, "policy", policies, 3, &form->policy_index, .full_width = true);
    cui_muted(ui, policy_explanation(form->policy_index));
    cui_select(ui, "subdomain-policy", subdomain_policies, 4, &form->subdomain_policy_index,
               .label = "Subdomains (sp)", .width = CUI_FILL);
    cui_number(ui, "percentage", &form->percentage, 0, 100, .label = "Anteil der Mails (pct)", .step = 10,
               .suffix = "%", .width = CUI_FILL);
}

static void report_fields(cui_ctx *ui, dmarc_form *form) {
    static const char *const failure_reporting[] = {
        "SPF und DKIM schlagen fehl (0)", "SPF oder DKIM schlägt fehl (1)", "DKIM schlägt fehl (d)", "SPF schlägt fehl (s)",
    };
    bool has_failure_addresses = form->failure_addresses[0] != '\0';

    cui_input(ui, "rua", form->aggregate_addresses, sizeof form->aggregate_addresses,
              .label = "Sammelberichte an (rua)", .placeholder = "dmarc@example.com", .icon = CUI_ICON_MAIL,
              .hint = "Tägliche Zusammenfassungen. Mehrere Adressen mit Komma trennen.",
              .error = dmarc_check_address_list(form->aggregate_addresses));
    cui_input(ui, "ruf", form->failure_addresses, sizeof form->failure_addresses,
              .label = "Fehlerberichte an (ruf)", .placeholder = "optional", .icon = CUI_ICON_MAIL,
              .hint = "Einzelberichte pro Mail; nur wenige Anbieter senden sie.",
              .error = dmarc_check_address_list(form->failure_addresses));
    cui_select(ui, "fo", failure_reporting, 4, &form->failure_reporting_index,
               .label = "Fehlerbericht senden, wenn (fo)", .disabled = !has_failure_addresses, .width = CUI_FILL);
}

static void alignment_fields(cui_ctx *ui, dmarc_form *form) {
    static const char *const alignments[] = { "Relaxed", "Strict" };
    cui_row(ui, .width = CUI_FILL, .gap = 16) {
        cui_column(ui, .width = CUI_FILL, .gap = 6) {
            cui_label(ui, "DKIM-Ausrichtung (adkim)");
            cui_segmented(ui, "adkim", alignments, 2, &form->dkim_alignment_index, .full_width = true);
        }
        cui_column(ui, .width = CUI_FILL, .gap = 6) {
            cui_label(ui, "SPF-Ausrichtung (aspf)");
            cui_segmented(ui, "aspf", alignments, 2, &form->spf_alignment_index, .full_width = true);
        }
    }
    cui_muted(ui, "Relaxed: Subdomains der Absenderdomain zählen mit. Strict: nur exakt dieselbe Domain.");
}

/* `loaded_from_domain` names the domain whose published record filled the
 * form, or is NULL when the form started from the defaults. */
static void form_card(cui_ctx *ui, dmarc_form *form, const char *loaded_from_domain) {
    char loaded_note[DNS_DOMAIN_CAPACITY + 64];
    cui_card(ui, .width = CUI_FILL, .gap = 12, .pad = 20) {
        cui_heading(ui, "Einstellungen", 4);
        if (loaded_from_domain) {
            snprintf(loaded_note, sizeof loaded_note, "Vorbelegt mit dem Eintrag von %s", loaded_from_domain);
            cui_badge(ui, loaded_note, .tone = CUI_TONE_INFO, .icon = CUI_ICON_REFRESH_CW);
        }
        policy_fields(ui, form);
        cui_separator(ui);
        report_fields(ui, form);
        cui_separator(ui);
        alignment_fields(ui, form);
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
static void record_hints(cui_ctx *ui, const char *domain, const dmarc_form *form) {
    char foreign_domain[DNS_DOMAIN_CAPACITY], authorization_host[DNS_DOMAIN_CAPACITY * 2 + 32], description[1024];

    if (!form->aggregate_addresses[0])
        cui_alert(ui, "Ohne rua-Adresse erhalten Sie keine Berichte",
                  .description = "Ohne sie sehen Sie nicht, ob alle eigenen Dienste DMARC bestehen, bevor Sie die Richtlinie verschärfen.",
                  .tone = CUI_TONE_WARNING);

    bool reports_go_elsewhere =
        dmarc_find_foreign_report_domain(domain, form->aggregate_addresses, foreign_domain, sizeof foreign_domain) ||
        dmarc_find_foreign_report_domain(domain, form->failure_addresses, foreign_domain, sizeof foreign_domain);
    if (domain[0] && reports_go_elsewhere) {
        snprintf(authorization_host, sizeof authorization_host, "%s._report._dmarc.%s", domain, foreign_domain);
        snprintf(description, sizeof description,
                 "Berichte an %s werden nur zugestellt, wenn dort der TXT-Eintrag %s mit dem Wert \"v=DMARC1\" existiert.",
                 foreign_domain, authorization_host);
        cui_alert(ui, "Berichte gehen an eine fremde Domain", .description = description, .tone = CUI_TONE_INFO);
    }
}

/* What the domain publishes today, from the last lookup of this domain. */
static void published_record(cui_ctx *ui, const lookup_report *report, const char *domain, const char *generated) {
    bool has_lookup_of_domain = report && domain[0] && strcmp(report->domain, domain) == 0;
    cui_separator(ui);
    cui_label(ui, "Aktuell veröffentlicht");
    if (!has_lookup_of_domain) {
        cui_muted(ui, "Für diese Domain noch nicht abgefragt. „Abfragen“ zeigt den bestehenden Eintrag.");
        return;
    }
    if (!report->mail.has_dmarc) {
        cui_badge(ui, "Kein DMARC-Eintrag", .tone = CUI_TONE_WARNING, .dot = true);
        return;
    }
    bool is_identical = strcmp(report->mail.dmarc_record, generated) == 0;
    bool is_equivalent = is_identical || dmarc_records_are_equivalent(report->mail.dmarc_record, generated);
    const char *comparison = is_identical    ? "Identisch mit dem neuen Eintrag"
                             : is_equivalent ? "Gleiche Wirkung, nur anders geschrieben"
                                             : "Weicht vom neuen Eintrag ab";
    cui_badge(ui, comparison, .tone = is_equivalent ? CUI_TONE_SUCCESS : CUI_TONE_INFO, .dot = true);
    cui_text(ui, report->mail.dmarc_record, .font = CUI_FONT_MONO, .size = 12, .color = CUI_COLOR_TEXT_SECONDARY);
}

static void result_card(cui_ctx *ui, const app_state *app, const char *domain) {
    char record[DMARC_RECORD_CAPACITY], host[DNS_DOMAIN_CAPACITY + 8];
    dmarc_settings settings = dmarc_settings_from_form(&app->dmarc);
    bool fits = dmarc_build_record(&settings, record, sizeof record);
    dmarc_record_host(domain, host, sizeof host);

    cui_card(ui, .width = CUI_FILL, .gap = 14, .pad = 20) {
        cui_heading(ui, "DNS-Eintrag", 4);
        if (!domain[0]) cui_muted(ui, "Oben eine Domain eingeben; bis dahin steht example.com als Platzhalter.");
        copyable_field(ui, "copy-host", "Host / Name", host);
        copyable_field(ui, "copy-type", "Typ", "TXT");
        if (fits) copyable_field(ui, "copy-value", "Wert", record);
        else cui_alert(ui, "Der Eintrag ist zu lang", .tone = CUI_TONE_DANGER);
        record_hints(ui, domain, &app->dmarc);
        published_record(ui, app->report, domain, record);
    }
}

/* ------------------------------------------------------------------------ */
/* Page                                                                     */
/* ------------------------------------------------------------------------ */

void dmarc_page(cui_ctx *ui, app_state *app) {
    char domain[DNS_DOMAIN_CAPACITY];
    app_current_domain(app, domain, sizeof domain);

    bool is_form_from_this_domain = app->is_dmarc_form_from_published && app->report &&
                                    strcmp(app->report->domain, domain) == 0;
    const char *loaded_from_domain = is_form_from_this_domain ? app->report->domain : NULL;

    cui_row(ui, .width = CUI_FILL, .gap = 16, .align = CUI_ALIGN_START) {
        cui_column(ui, .width = CUI_GROW(1), .min_width = 320) { form_card(ui, &app->dmarc, loaded_from_domain); }
        cui_column(ui, .width = CUI_GROW(1), .min_width = 320) { result_card(ui, app, domain); }
    }
}
