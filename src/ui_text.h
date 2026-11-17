/* Every text the window shows, in German and US English. The core modules
 * return codes (dns_status, report_error); this module words them.
 *
 * Plain texts and printf formats live in two structs whose members are all
 * `const char *`, so a test can walk them as arrays: no text may be missing,
 * and a format must take the same arguments in every language. */
#ifndef UI_TEXT_H
#define UI_TEXT_H

#include "dns_lookup.h"
#include "report_file.h"

#include <stddef.h>

typedef enum ui_language {
    UI_LANGUAGE_GERMAN = 0,
    UI_LANGUAGE_ENGLISH,         /* US English */
    UI_LANGUAGE_COUNT,
} ui_language;

typedef struct ui_strings {
    /* window */
    const char *domain_label, *domain_error, *extra_names_label, *extra_names_hint, *look_up_button;
    const char *page_records, *page_dmarc, *page_reports;

    /* records page */
    const char *looking_up, *no_lookup_title, *no_lookup_description;
    const char *present, *missing, *name_unknown;
    const char *incoming_mail_card, *no_mail_exchanger, *no_spf, *no_dmarc, *unknown_dkim_selectors;
    const char *column_type, *column_name, *column_ttl, *column_value;
    const char *source_resolver;
    const char *some_queries_failed, *no_records_found;
    const char *status_no_data, *status_no_such_domain, *status_failure;

    /* DMARC page */
    const char *settings_heading, *policy_label, *policy_none, *policy_quarantine, *policy_reject;
    const char *subdomain_label, *subdomain_like_domain, *percentage_label;
    const char *rua_label, *rua_hint, *ruf_label, *ruf_placeholder, *ruf_hint, *address_error;
    const char *fo_label, *fo_all_fail, *fo_any_fails, *fo_dkim_fails, *fo_spf_fails;
    const char *adkim_label, *aspf_label, *alignment_hint;
    const char *record_heading, *placeholder_domain_note, *host_label, *record_too_long;
    const char *no_rua_title, *no_rua_description, *foreign_reports_title;
    const char *published_heading, *not_looked_up, *no_dmarc_record;
    const char *identical, *equivalent, *differs;

    /* reports page */
    const char *drop_title, *drop_description, *open_dialog_title, *remove_all, *reports_intro;
    const char *messages_reported, *dmarc_passed, *dmarc_failed, *reports_metric;
    const char *all_pass_title, *all_pass_description, *some_fail_title, *some_fail_description;
    const char *passed, *failed, *no_signature;
    const char *column_sender_ip, *column_messages, *column_spf, *column_dkim, *column_disposition;
    const char *error_cannot_open, *error_cannot_read, *error_too_large, *error_broken_archive;
    const char *error_not_xml, *error_not_a_report, *error_out_of_memory;

    const char *date_format;     /* strftime: "%d.%m.%Y", "%m/%d/%Y" */
} ui_strings;

/* printf formats; the comment names the arguments, the same in every language. */
typedef struct ui_formats {
    const char *mail_exchangers_one;     /* %d count */
    const char *mail_exchangers_other;   /* %d count */
    const char *dkim_selectors;          /* %s list */
    const char *dkim_missing;            /* %s list of selectors tried */
    const char *filter_all;              /* %d count */
    const char *source_direct;           /* %s name server */
    const char *failed_queries;          /* %s list */
    const char *loaded_from;             /* %s domain */
    const char *foreign_reports;         /* %s report domain, %s authorization host */
    const char *reports_loaded_one;      /* %d count */
    const char *reports_loaded_other;    /* %d count */
    const char *reports_already_loaded;  /* %d count */
    const char *reports_unreadable;      /* %d count, %s file name, %s reason */
    const char *passing_share;           /* %ld messages, %.0f percent */
} ui_formats;

typedef struct ui_text {
    ui_strings strings;
    ui_formats formats;
} ui_text;

const ui_text *ui_text_for(ui_language language);

/* German when the system's preferred language is German, else English. */
ui_language ui_system_language(void);

const char *ui_dns_status_message(const ui_text *text, dns_status status);
const char *ui_report_error_message(const ui_text *text, report_error error);

/* Picks the singular or plural format by `count`. */
const char *ui_plural(long count, const char *one, const char *other);

/* A day in the language's date format. */
void ui_format_day(const ui_text *text, long long seconds, char *out, size_t capacity);

#endif
