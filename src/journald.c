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

#include <syslog.h>

#include <assert.h>

enum EventdJournaldJournals {
    EVENTD_JOURNALD_JOURNAL_SYSTEM = 0x1,
    EVENTD_JOURNALD_JOURNAL_USER   = 0x2
};

enum EventdJournaldEvents {
    EVENTD_JOURNALD_EVENT_UNIT  = 0x1,
    EVENTD_JOURNALD_EVENT_ERROR = 0x2
};

struct _EventdPluginContext {
    EventdPluginCoreContext *core;
    EventdPluginCoreInterface *core_interface;

    gchar *uid;

    gboolean local_only;
    guint64 journals;
    guint64 events;

    gboolean ok;
    sd_journal *journal;
    GSource *source;
};

static EventdPluginContext *
_eventd_journald_init(EventdPluginCoreContext *core, EventdPluginCoreInterface *core_interface)
{
    EventdPluginContext *context;

    context = g_new0(EventdPluginContext, 1);

    context->uid = g_strdup_printf("%u", getuid());

    context->core = core;
    context->core_interface= core_interface;

    return context;
}

static void
_eventd_journald_uninit(EventdPluginContext *context)
{
    g_free(context->uid);

    g_free(context);
}

static gboolean
_eventd_journald_new_entry(gint fd, GIOCondition events, EventdPluginContext *context)
{
    if (!context->ok)
        return G_SOURCE_REMOVE;

#define vars(call)    \
    call(priority);   \
    call(comm);       \
    call(uid);        \
    call(message);    \
    call(message_id); \
    call(hostname);   \
    call(unit);       \
    call(result);     \
    call(_dummy)

#define declare(var) \
    gchar *var = NULL
    vars(declare);
#undef declare

    EventdEvent *event = NULL;

    for (;;) {
        int ret;
        const char *kind;
        const void *data;
        size_t length;
        guint64 make_event = 0;

        if (event)
            g_object_unref(event);
        event = NULL;

#define safe_free(var) \
    g_free(var);       \
    var = NULL
        vars(safe_free);
#undef safe_free

        ret = sd_journal_process(context->journal);
        switch (ret) {
            case SD_JOURNAL_NOP:
                return G_SOURCE_CONTINUE;
            case SD_JOURNAL_APPEND:
                break;
            case SD_JOURNAL_INVALIDATE:
                /* FIXME: correct? */
                break;
            default:
                g_warning("unhandled process return value: %d; forging ahead", ret);
                break;
        }

        ret = sd_journal_next(context->journal);
        if (!ret)
            break;
        if (ret < 0) {
            g_warning("failed to seek within the journal: %s", g_strerror(-ret));
            context->ok = FALSE;
            return G_SOURCE_REMOVE;
        }

#define sd_read_field(field, var, req)                                  \
    ret = sd_journal_get_data(context->journal, field, &data, &length); \
    if (!ret) {                                                         \
        var = g_malloc0((length - sizeof(field) + 1) * sizeof(gchar));  \
        memcpy(var, data + sizeof(field), length - sizeof(field));      \
    } else if (ret == -ENOENT) {                                        \
        var = NULL;                                                     \
        if (req)                                                        \
            continue;                                                   \
    } else {                                                            \
        continue;                                                       \
    }

        sd_read_field("PRIORITY", priority, TRUE);
        int prio = *priority - '0';
        if ((prio <= LOG_ERR) && (context->events & EVENTD_JOURNALD_EVENT_ERROR)) {
            kind = "error";
            make_event = EVENTD_JOURNALD_EVENT_ERROR;
        } else {
            sd_read_field("_COMM", comm, TRUE);
            if (g_strcmp0(comm, "systemd"))
                continue;

            sd_read_field("_UID", uid, TRUE);
            if ((!g_strcmp0(uid, "0") && (context->journals & EVENTD_JOURNALD_JOURNAL_SYSTEM)) ||
                (!g_strcmp0(uid, context->uid) && (context->journals & EVENTD_JOURNALD_JOURNAL_USER))) {
                kind = "unit";
                make_event = EVENTD_JOURNALD_EVENT_UNIT;
            }
        }

        if (!make_event)
            continue;

        sd_read_field("MESSAGE", message, TRUE);
        sd_read_field("MESSAGE_ID", message_id, FALSE);
        sd_read_field("_HOSTNAME", hostname, TRUE);
        /* TODO: read _SOURCE_REALTIME_TIMESTAMP */

        event = eventd_event_new("journal", kind);
        eventd_event_add_data(event, g_strdup("priority"), g_strdup(priority));
        eventd_event_add_data(event, g_strdup("message"), g_strdup(message));
        eventd_event_add_data(event, g_strdup("message_id"), g_strdup(message_id ? message_id : ""));
        eventd_event_add_data(event, g_strdup("hostname"), g_strdup(hostname));

        switch (make_event) {
            case EVENTD_JOURNALD_EVENT_ERROR:
                sd_read_field("_SYSTEMD_USER_UNIT", unit, FALSE);
                if (!unit) {
                    sd_read_field("_SYSTEMD_UNIT", unit, TRUE);
                }

                if (unit) {
                    eventd_event_add_data(event, g_strdup("unit"), g_strdup(unit));
                }

                break;
            case EVENTD_JOURNALD_EVENT_UNIT:
                sd_read_field("USER_UNIT", unit, TRUE);
                sd_read_field("RESULT", result, FALSE);

                eventd_event_add_data(event, g_strdup("unit"), g_strdup(unit));
                eventd_event_add_data(event, g_strdup("result"), g_strdup(result ? result : ""));

                break;
            case 0:
                assert(0);
                continue;
            default:
                g_warning("unimplemented event handler: %" G_GUINT64_FORMAT, make_event);
                continue;
        }

        eventd_event_set_timeout(event, 1000 /* TODO: timeout */);

        if (!eventd_plugin_core_push_event(context->core, context->core_interface, event))
            g_warning("failed to push an event into the queue: %s", message);
    }

    vars(g_free);
    if (event)
        g_object_unref(event);

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
    /* g_unix_fd_source_new uses GUnixFDSourceFunc as its callback function. */
    g_source_set_callback(context->source, (GSourceFunc)_eventd_journald_new_entry, context, NULL);
    g_source_attach(context->source, NULL);
}

static void
_eventd_journald_stop(EventdPluginContext *context)
{
    context->ok = FALSE;

    sd_journal_close(context->journal);
    context->journal = NULL;

    g_source_destroy(context->source);
    g_source_unref(context->source);
    context->source = NULL;
}

static void
_eventd_journald_global_parse(EventdPluginContext *context, GKeyFile *config_file)
{
    gboolean local_only = TRUE;
    gchar **journals = NULL;
    gchar **events = NULL;

    if (!g_key_file_has_group(config_file, "Journald"))
        return;

    if (libeventd_config_key_file_get_boolean(config_file, "Journald", "LocalOnly", &local_only) < 0) {
        context->local_only = TRUE;
    } else {
        context->local_only = local_only;
    }

    libeventd_config_key_file_get_string_list(config_file, "Journald", "Journals", &journals, NULL);

    if (journals) {
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

            ++journal_iter;
        }
    } else {
        context->journals = EVENTD_JOURNALD_JOURNAL_SYSTEM
                          | EVENTD_JOURNALD_JOURNAL_USER;
    }
    g_strfreev(journals);
    journals = NULL;

    if (!context->journals)
        g_warning("not watching any journals");

    libeventd_config_key_file_get_string_list(config_file, "Journald", "Events", &events, NULL);

    if (events) {
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

            ++event_iter;
        }
    } else {
        context->events = EVENTD_JOURNALD_EVENT_UNIT
                        | EVENTD_JOURNALD_EVENT_ERROR;
    }
    g_strfreev(events);
    events = NULL;

    if (!context->journals)
        g_warning("not watching any events");
}

#define JOURNALD_EXPORT __attribute__((__visibility__("default")))

JOURNALD_EXPORT const gchar *eventd_plugin_id = "eventd-journald";
JOURNALD_EXPORT
void
eventd_plugin_get_interface(EventdPluginInterface *interface)
{
    eventd_plugin_interface_add_init_callback(interface, _eventd_journald_init);
    eventd_plugin_interface_add_uninit_callback(interface, _eventd_journald_uninit);

    eventd_plugin_interface_add_start_callback(interface, _eventd_journald_start);
    eventd_plugin_interface_add_stop_callback(interface, _eventd_journald_stop);

    eventd_plugin_interface_add_global_parse_callback(interface, _eventd_journald_global_parse);
}
