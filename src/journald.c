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
#include <glib-unix.h>

#include <libeventd-config.h>
#include <libeventd-event.h>
#include <eventd-plugin.h>

#include <systemd/sd-journal.h>

enum EventdJournaldJournals {
    EVENTD_JOURNALD_JOURNAL_SYSTEM = 0x1,
    EVENTD_JOURNALD_JOURNAL_USER   = 0x2
};

enum EventdJournaldEvents {
    EVENTD_JOURNALD_EVENT_UNIT  = 0x1,
    EVENTD_JOURNALD_EVENT_ERROR = 0x2
};

struct _EventdPluginContext {
    EventdCoreContext *core;
    EventdCoreInterface *core_interface;

    gboolean local_only;
    guint64 journals;
    guint64 events;

    gboolean ok;
    sd_journal *journal;
    GSource *source;
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
    g_free(context);
}

static gboolean
_eventd_journald_new_entry(EventdPluginContext *context)
{
    if (!context->ok)
        return G_SOURCE_REMOVE;

    for (;;) {
        int i;
        int ret = sd_journal_next(context->journal);

        if (!ret)
            break;
        if (ret < 0) {
            g_warning("failed to seek within the journal: %s", g_strerror(-ret));
            context->ok = FALSE;
            return G_SOURCE_REMOVE;
        }

        for (i = 0; i < ret; ++i) {
            const void *data;
            size_t length;

            /* TODO: parse the data out */
            /* TODO: make an event */
        }
    }

    return G_SOURCE_CONTINUE;
}

static void
_eventd_journald_start(EventdPluginContext *context)
{
    int journal_flags = 0;
    int ret;
    int fd;
    int events;

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
        g_warning("failed to open the journal: %s", g_strerror(-ret));
        return;
    }
    ret = sd_journal_seek_tail(context->journal);
    if (ret < 0) {
        g_warning("failed to seek to the end of the journal: %s", g_strerror(-ret));
        return;
    }

    fd = sd_journal_get_fd(context->journal);
    if (fd < 0) {
        g_warning("failed to get a file descriptor for the journal: %s", g_strerror(-fd));
        return;
    }
    events = sd_journal_get_events(context->journal);
    if (events < 0) {
        g_warning("failed to get events for the journal: %s", g_strerror(-events));
        return;
    }

    context->ok = TRUE;

    context->source = g_unix_fd_source_new(fd, events);
    g_source_set_callback(context->source, (GSourceFunc)_eventd_journald_new_entry, context, NULL);
}

static void
_eventd_journald_stop(EventdPluginContext *context)
{
    context->ok = FALSE;

    sd_journal_close(context->journal);
    context->journal = NULL;

    g_source_unref(context->source);
    context->source = NULL;
}

static void
_eventd_journald_global_parse(EventdPluginContext *context, GKeyFile *config_file)
{
    gboolean local_only;
    gchar **journals;
    gchar **events;

    if (!g_key_file_has_group(config_file, "Journald"))
        return;

    if (libeventd_config_key_file_get_boolean(config_file, "Journald", "LocalOnly", &local_only) < 0) {
        context->local_only = local_only;
    } else {
        context->local_only = TRUE;
    }

    if (libeventd_config_key_file_get_string_list(config_file, "Journald", "Journals", &journals, NULL) < 0) {
        gchar **journal_iter = journals;

        while (*journal_iter) {

            if (FALSE) {}

#define eventd_journald_journals(call)             \
    call("system", EVENTD_JOURNALD_JOURNAL_SYSTEM) \
    call("user", EVENTD_JOURNALD_JOURNAL_USER)

#define check_journal(name, flag)             \
    else if (!g_strcmp0(name, *journal_iter)) \
        context->journals |= flag;

            eventd_journald_journals(check_journal)

#undef check_journal

            else
                g_warning("unknown journal '%s'", *journal_iter);
        }
    } else {
        context->journals = EVENTD_JOURNALD_JOURNAL_SYSTEM
                          | EVENTD_JOURNALD_JOURNAL_USER;
    }
    g_strfreev(journals);

    if (!context->journals)
        g_warning("not watching any journals");

    if (libeventd_config_key_file_get_string_list(config_file, "Journald", "Events", &events, NULL) < 0) {
        gchar **event_iter = events;

        while (*event_iter) {

            if (FALSE) {}

#define eventd_journald_events(call)           \
    call("unit", EVENTD_JOURNALD_EVENT_UNIT)   \
    call("error", EVENTD_JOURNALD_EVENT_ERROR)

#define check_event(name, flag)             \
    else if (!g_strcmp0(name, *event_iter)) \
        context->events |= flag;

            eventd_journald_events(check_event)

#undef check_journal

            else
                g_warning("unknown event '%s'", *event_iter);
        }
    } else {
        context->events = EVENTD_JOURNALD_EVENT_UNIT
                        | EVENTD_JOURNALD_EVENT_ERROR;
    }
    g_strfreev(events);

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
}
