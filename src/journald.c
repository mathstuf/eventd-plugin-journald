/*
 * eventd-plugin-journald - Collect events from systemd's journal
 *
 * Copyright 2015 Ben Boeckel
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see http://www.gnu.org/licenses/.
 */

#include <glib.h>
#include <glib-object.h>

#include <libeventd-config.h>
#include <libeventd-event.h>
#include <eventd-plugin.h>

#include <systemd/sd-journal.h>

enum EventdJournaldJournals {
    EVENTD_JOURNALD_JOURNAL_SYSTEM = 0x1,
    EVENTD_JOURNALD_JOURNAL_USER   = 0x2
};
#define eventd_journald_journals(call) \
    call("system", EVENTD_JOURNALD_JOURNAL_SYSTEM) \
    call("user", EVENTD_JOURNALD_JOURNAL_USER)

enum EventdJournaldEvents {
    EVENTD_JOURNALD_EVENT_START = 0x1,
    EVENTD_JOURNALD_EVENT_STOP  = 0x2,
    EVENTD_JOURNALD_EVENT_ERROR = 0x4
};
#define eventd_journald_events(call) \
    call("start", EVENTD_JOURNALD_EVENT_START) \
    call("stop", EVENTD_JOURNALD_EVENT_STOP) \
    call("error", EVENTD_JOURNALD_EVENT_ERROR)

struct _EventdPluginContext {
    EventdCoreContext *core;
    EventdCoreInterface *core_interface;

    gboolean local_only;
    guint64 journals;
    guint64 events;

    sd_journal *journal;
};

static EventdPluginContext *
_eventd_journald_init(EventdCoreContext *core, EventdCoreInterface *core_interface)
{
    EventdPluginContext *context;

    context = g_new0(EventdPluginContext, 1);

    context->core = core;
    context->core_interface= core_interface;

    return context;
}

static void
_eventd_journald_uninit(EventdPluginContext *context)
{
    sd_journal_close(context->journal);

    g_free(context);
}

static void
_eventd_journald_start(EventdPluginContext *context)
{
    int journal_flags = 0;
    int ret;

    if (!context->journals || !context->events)
        return;

    if (context->local_only)
        journal_flags |= SD_JOURNAL_LOCAL_ONLY;
    if (context->journals & EVENTD_JOURNALD_JOURNAL_SYSTEM)
        journal_flags |= SD_JOURNAL_SYSTEM;
    if (context->journals & EVENTD_JOURNALD_JOURNAL_USER)
        journal_flags |= SD_JOURNAL_CURRENT_USER;

    ret = sd_journal_open(&context->journal, journal_flags);
    if (ret < 0) {
        g_error ("failed to open the journal: %s", g_strerror(-ret));
        return;
    }
    sd_journal_seek_tail(context->journal);
}

static void
_eventd_journald_stop(EventdPluginContext *context)
{
    sd_journal_close(context->journal);
    context->journal = NULL;
}

static void
_eventd_journald_global_parse(EventdPluginContext *context, GKeyFile *config_file)
{
    gboolean local_only;
    gchar *journals_conf;
    gchar *events_conf;

    if (!g_key_file_has_group(config_file, "Journald"))
        return;

    if (libeventd_config_key_file_get_boolean(config_file, "Journald", "LocalOnly", &local_only) < 0) {
        context->local_only = local_only;
    } else {
        context->local_only = TRUE;
    }

    if (libeventd_config_key_file_get_string(config_file, "Journald", "Journals", &journals_conf) < 0) {
        gchar **journals = g_strsplit(journals_conf, ",", 0);
        gchar **journal_iter = journals;

        while (*journal_iter) {

            if (FALSE) {}

#define check_journal(name, flag)             \
    else if (!g_strcmp0(name, *journal_iter)) \
        context->journals |= flag;

            eventd_journald_journals(check_journal)

#undef check_journal

            else
                g_warning("unknown journal '%s'", *journal_iter);
        }

        g_strfreev(journals);
    } else {
        context->journals = EVENTD_JOURNALD_JOURNAL_SYSTEM
                          | EVENTD_JOURNALD_JOURNAL_USER;
    }
    g_free(journals_conf);

    if (!context->journals)
        g_warning("not watching any journals");

    if (libeventd_config_key_file_get_string(config_file, "Journald", "Events", &events_conf) < 0) {
        gchar **events = g_strsplit(events_conf, ",", 0);
        gchar **event_iter = events;

        while (*event_iter) {

            if (FALSE) {}

#define check_event(name, flag)             \
    else if (!g_strcmp0(name, *event_iter)) \
        context->events |= flag;

            eventd_journald_events(check_event)

#undef check_journal

            else
                g_warning("unknown event '%s'", *event_iter);
        }

        g_strfreev(events);
    } else {
        context->events = EVENTD_JOURNALD_EVENT_START
                        | EVENTD_JOURNALD_EVENT_STOP
                        | EVENTD_JOURNALD_EVENT_ERROR;
    }
    g_free(events_conf);

    if (!context->journals)
        g_warning("not watching any events");
}

#define JOURNALD_EXPORT __attribute__((__visibility__("default")))

JOURNALD_EXPORT const gchar *eventd_plugin_id = "eventd-journald";
JOURNALD_EXPORT
void
eventd_plugin_get_interface(EventdPluginInterface *interface)
{
    libeventd_plugin_interface_add_init_callback(interface, _eventd_journald_init);
    libeventd_plugin_interface_add_uninit_callback(interface, _eventd_journald_uninit);

    libeventd_plugin_interface_add_start_callback(interface, _eventd_journald_start);
    libeventd_plugin_interface_add_stop_callback(interface, _eventd_journald_stop);

    libeventd_plugin_interface_add_global_parse_callback(interface, _eventd_journald_global_parse);
    /*libeventd_plugin_interface_add_event_parse_callback(interface, _eventd_journald_event_parse);*/
    /*libeventd_plugin_interface_add_config_reset_callback(interface, _eventd_journald_config_reset);*/
}
