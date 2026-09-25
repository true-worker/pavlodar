import django.db.models.deletion
import django.utils.timezone
import helpdesk.models
import helpdesk.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Checklist',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100, verbose_name='Name')),
            ],
            options={
                'verbose_name': 'Checklist',
                'verbose_name_plural': 'Checklists',
            },
        ),
        migrations.CreateModel(
            name='ChecklistTemplate',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100, verbose_name='Name')),
                ('task_list', models.JSONField(validators=[helpdesk.models.is_a_list_without_empty_element], verbose_name='Task List')),
            ],
            options={
                'verbose_name': 'Checklist Template',
                'verbose_name_plural': 'Checklist Templates',
            },
        ),
        migrations.CreateModel(
            name='CustomField',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.SlugField(help_text='As used in the database and behind the scenes. Must be unique and consist of only lowercase letters with no punctuation.', unique=True, verbose_name='Field Name')),
                ('label', models.CharField(help_text='The display label for this field', max_length=30, verbose_name='Label')),
                ('help_text', models.TextField(blank=True, help_text='Shown to the user when editing the ticket', null=True, verbose_name='Help Text')),
                ('data_type', models.CharField(choices=[('varchar', 'Character (single line)'), ('text', 'Text (multi-line)'), ('integer', 'Integer'), ('decimal', 'Decimal'), ('list', 'List'), ('boolean', 'Boolean (checkbox yes/no)'), ('date', 'Date'), ('time', 'Time'), ('datetime', 'Date & Time'), ('email', 'E-Mail Address'), ('url', 'URL'), ('ipaddress', 'IP Address'), ('slug', 'Slug')], help_text='Allows you to restrict the data entered into this field', max_length=100, verbose_name='Data Type')),
                ('max_length', models.IntegerField(blank=True, null=True, verbose_name='Maximum Length (characters)')),
                ('decimal_places', models.IntegerField(blank=True, help_text='Only used for decimal fields', null=True, verbose_name='Decimal Places')),
                ('empty_selection_list', models.BooleanField(default=False, help_text='Only for List: adds an empty first entry to the choices list, which enforces that the user makes an active choice.', verbose_name='Add empty first choice to List?')),
                ('list_values', models.TextField(blank=True, help_text='For list fields only. Enter one option per line.', null=True, verbose_name='List Values')),
                ('ordering', models.IntegerField(blank=True, help_text='Lower numbers are displayed first; higher numbers are listed later', null=True, verbose_name='Ordering')),
                ('required', models.BooleanField(default=False, help_text='Does the user have to enter a value for this field?', verbose_name='Required?')),
                ('staff_only', models.BooleanField(default=False, help_text='If this is ticked, then the public submission form will NOT show this field', verbose_name='Staff Only?')),
            ],
            options={
                'verbose_name': 'Custom field',
                'verbose_name_plural': 'Custom fields',
            },
        ),
        migrations.CreateModel(
            name='EmailTemplate',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('template_name', models.CharField(max_length=100, verbose_name='Template Name')),
                ('subject', models.CharField(help_text='This will be prefixed with "[ticket.ticket] ticket.title". We recommend something simple such as "(Updated") or "(Closed)" - the same context is available as in plain_text, below.', max_length=100, verbose_name='Subject')),
                ('heading', models.CharField(help_text='In HTML e-mails, this will be the heading at the top of the email - the same context is available as in plain_text, below.', max_length=100, verbose_name='Heading')),
                ('plain_text', models.TextField(help_text='The context available to you includes {{ ticket }}, {{ queue }}, and depending on the time of the call: {{ resolution }} or {{ comment }}.', verbose_name='Plain Text')),
                ('html', models.TextField(help_text='The same context is available here as in plain_text, above.', verbose_name='HTML')),
                ('locale', models.CharField(blank=True, help_text='Locale of this template.', max_length=10, null=True, verbose_name='Locale')),
            ],
            options={
                'verbose_name': 'e-mail template',
                'verbose_name_plural': 'e-mail templates',
                'ordering': ('template_name', 'locale'),
            },
        ),
        migrations.CreateModel(
            name='EscalationExclusion',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100, verbose_name='Name')),
                ('date', models.DateField(help_text='Date on which escalation should not happen', verbose_name='Date')),
            ],
            options={
                'verbose_name': 'Escalation exclusion',
                'verbose_name_plural': 'Escalation exclusions',
            },
        ),
        migrations.CreateModel(
            name='FollowUp',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('date', models.DateTimeField(default=django.utils.timezone.now, verbose_name='Date')),
                ('title', models.CharField(blank=True, max_length=200, null=True, verbose_name='Title')),
                ('comment', models.TextField(blank=True, null=True, verbose_name='Comment')),
                ('public', models.BooleanField(blank=True, default=False, help_text='Public tickets are viewable by the submitter and all staff, but non-public tickets can only be seen by staff.', verbose_name='Public')),
                ('new_status', models.IntegerField(blank=True, choices=[(1, 'Open'), (2, 'Reopened'), (3, 'Resolved'), (4, 'Closed'), (5, 'Duplicate')], help_text='If the status was changed, what was it changed to?', null=True, verbose_name='New Status')),
                ('message_id', models.CharField(blank=True, editable=False, help_text="The Message ID of the submitter's email.", max_length=256, null=True, verbose_name='E-Mail ID')),
                ('time_spent', models.DurationField(blank=True, help_text='Time spent on this follow up', null=True)),
                ('email_recipients', models.JSONField(blank=True, default=None, help_text='Addresses successfully notified by e-mail about this follow-up. Null means recipients were not recorded.', null=True, verbose_name='E-Mail Recipients')),
            ],
            options={
                'verbose_name': 'Follow-up',
                'verbose_name_plural': 'Follow-ups',
                'ordering': ('date',),
            },
        ),
        migrations.CreateModel(
            name='FollowUpAttachment',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('file', models.FileField(max_length=1000, upload_to=helpdesk.models.attachment_path, validators=[helpdesk.validators.validate_file_extension], verbose_name='File')),
                ('filename', models.CharField(blank=True, max_length=1000, verbose_name='Filename')),
                ('mime_type', models.CharField(blank=True, max_length=255, verbose_name='MIME Type')),
                ('size', models.IntegerField(blank=True, help_text='Size of this file in bytes', verbose_name='Size')),
            ],
            options={
                'verbose_name': 'Attachment',
                'verbose_name_plural': 'Attachments',
                'ordering': ('filename',),
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='IgnoreEmail',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100, verbose_name='Name')),
                ('date', models.DateField(blank=True, editable=False, help_text='Date on which this e-mail address was added', verbose_name='Date')),
                ('email_address', models.CharField(help_text='Enter a full e-mail address, or portions with wildcards, eg *@domain.com or postmaster@*.', max_length=150, verbose_name='E-Mail Address')),
                ('keep_in_mailbox', models.BooleanField(blank=True, default=False, help_text='Do you want to save emails from this address in the mailbox? If this is unticked, emails from this address will be deleted.', verbose_name='Save Emails in Mailbox?')),
            ],
            options={
                'verbose_name': 'Ignored e-mail address',
                'verbose_name_plural': 'Ignored e-mail addresses',
            },
        ),
        migrations.CreateModel(
            name='KBCategory',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100, verbose_name='Name of the category')),
                ('title', models.CharField(max_length=100, verbose_name='Title on knowledgebase page')),
                ('slug', models.SlugField(verbose_name='Slug')),
                ('description', models.TextField(verbose_name='Description')),
                ('public', models.BooleanField(default=True, verbose_name='Is KBCategory publicly visible?')),
            ],
            options={
                'verbose_name': 'Knowledge base category',
                'verbose_name_plural': 'Knowledge base categories',
                'ordering': ('title',),
            },
        ),
        migrations.CreateModel(
            name='KBIAttachment',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('file', models.FileField(max_length=1000, upload_to=helpdesk.models.attachment_path, validators=[helpdesk.validators.validate_file_extension], verbose_name='File')),
                ('filename', models.CharField(blank=True, max_length=1000, verbose_name='Filename')),
                ('mime_type', models.CharField(blank=True, max_length=255, verbose_name='MIME Type')),
                ('size', models.IntegerField(blank=True, help_text='Size of this file in bytes', verbose_name='Size')),
            ],
            options={
                'verbose_name': 'Attachment',
                'verbose_name_plural': 'Attachments',
                'ordering': ('filename',),
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='KBItem',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=100, verbose_name='Title')),
                ('question', models.TextField(verbose_name='Question')),
                ('answer', models.TextField(verbose_name='Answer')),
                ('votes', models.IntegerField(default=0, help_text='Total number of votes cast for this item', verbose_name='Votes')),
                ('recommendations', models.IntegerField(default=0, help_text='Number of votes for this item which were POSITIVE.', verbose_name='Positive Votes')),
                ('last_updated', models.DateTimeField(blank=True, help_text='The date on which this question was most recently changed.', verbose_name='Last Updated')),
                ('order', models.PositiveIntegerField(blank=True, null=True, verbose_name='Order')),
                ('enabled', models.BooleanField(default=True, verbose_name='Enabled to display to users')),
            ],
            options={
                'verbose_name': 'Knowledge base item',
                'verbose_name_plural': 'Knowledge base items',
                'ordering': ('order', 'title'),
            },
        ),
        migrations.CreateModel(
            name='PreSetReply',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(help_text='Only used to assist users with selecting a reply - not shown to the user.', max_length=100, verbose_name='Name')),
                ('body', models.TextField(help_text='Context available: {{ ticket }} - ticket object (eg {{ ticket.title }}); {{ queue }} - The queue; and {{ user }} - the current user.', verbose_name='Body')),
            ],
            options={
                'verbose_name': 'Pre-set reply',
                'verbose_name_plural': 'Pre-set replies',
                'ordering': ('name',),
            },
        ),
        migrations.CreateModel(
            name='Queue',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=100, verbose_name='Title')),
                ('slug', models.SlugField(help_text="This slug is used when building ticket ID's. Once set, try not to change it or e-mailing may get messy.", unique=True, verbose_name='Slug')),
                ('email_address', models.EmailField(blank=True, help_text='All outgoing e-mails for this queue will use this e-mail address. If you use IMAP or POP3, this should be the e-mail address for that mailbox.', max_length=254, null=True, verbose_name='E-Mail Address')),
                ('locale', models.CharField(blank=True, help_text='Locale of this queue. All correspondence in this queue will be in this language.', max_length=10, null=True, verbose_name='Locale')),
                ('allow_public_submission', models.BooleanField(blank=True, default=False, help_text='Should this queue be listed on the public submission form?', verbose_name='Allow Public Submission?')),
                ('allow_email_submission', models.BooleanField(blank=True, default=False, help_text='Do you want to poll the e-mail box below for new tickets?', verbose_name='Allow E-Mail Submission?')),
                ('escalate_days', models.IntegerField(blank=True, help_text='For tickets which are not held, how often do you wish to increase their priority? Set to 0 for no escalation.', null=True, verbose_name='Escalation Days')),
                ('new_ticket_cc', models.CharField(blank=True, help_text='If an e-mail address is entered here, then it will receive notification of all new tickets created for this queue. Enter a comma between multiple e-mail addresses.', max_length=200, null=True, verbose_name='New Ticket CC Address')),
                ('updated_ticket_cc', models.CharField(blank=True, help_text='If an e-mail address is entered here, then it will receive notification of all activity (new tickets, closed tickets, updates, reassignments, etc) for this queue. Separate multiple addresses with a comma.', max_length=200, null=True, verbose_name='Updated Ticket CC Address')),
                ('enable_notifications_on_email_events', models.BooleanField(blank=True, default=False, help_text='When an email arrives to either create a ticket or to interact with an existing discussion. Should email notifications be sent ? Note: the new_ticket_cc and updated_ticket_cc work independently of this feature', verbose_name='Notify contacts when email updates arrive')),
                ('email_box_type', models.CharField(blank=True, choices=[('pop3', 'POP 3'), ('imap', 'IMAP'), ('oauth', 'IMAP OAUTH'), ('local', 'Local Directory')], help_text='E-Mail server type for creating tickets automatically from a mailbox - both POP3 and IMAP are supported, as well as reading from a local directory.', max_length=5, null=True, verbose_name='E-Mail Box Type')),
                ('email_box_host', models.CharField(blank=True, help_text='Your e-mail server address - either the domain name or IP address. May be "localhost".', max_length=200, null=True, verbose_name='E-Mail Hostname')),
                ('email_box_port', models.IntegerField(blank=True, help_text='Port number to use for accessing e-mail. Default for POP3 is "110", and for IMAP is "143". This may differ on some servers. Leave it blank to use the defaults.', null=True, verbose_name='E-Mail Port')),
                ('email_box_ssl', models.BooleanField(blank=True, default=False, help_text='Whether to use SSL for IMAP or POP3 - the default ports when using SSL are 993 for IMAP and 995 for POP3.', verbose_name='Use SSL for E-Mail?')),
                ('email_box_user', models.CharField(blank=True, help_text='Username for accessing this mailbox.', max_length=200, null=True, verbose_name='E-Mail Username')),
                ('email_box_pass', models.CharField(blank=True, help_text='Password for the above username', max_length=200, null=True, verbose_name='E-Mail Password')),
                ('email_box_imap_folder', models.CharField(blank=True, help_text='If using IMAP, what folder do you wish to fetch messages from? This allows you to use one IMAP account for multiple queues, by filtering messages on your IMAP server into separate folders. Default: INBOX.', max_length=100, null=True, verbose_name='IMAP Folder')),
                ('email_box_local_dir', models.CharField(blank=True, help_text='If using a local directory, what directory path do you wish to poll for new email? Example: /var/lib/mail/helpdesk/', max_length=200, null=True, verbose_name='E-Mail Local Directory')),
                ('permission_name', models.CharField(blank=True, editable=False, help_text='Name used in the django.contrib.auth permission system', max_length=72, null=True, verbose_name='Django auth permission name')),
                ('email_box_interval', models.IntegerField(blank=True, default='5', help_text='How often do you wish to check this mailbox? (in Minutes)', null=True, verbose_name='E-Mail Check Interval')),
                ('email_box_last_check', models.DateTimeField(blank=True, editable=False, null=True)),
                ('socks_proxy_type', models.CharField(blank=True, choices=[('socks4', 'SOCKS4'), ('socks5', 'SOCKS5')], help_text='SOCKS4 or SOCKS5 allows you to proxy your connections through a SOCKS server.', max_length=8, null=True, verbose_name='Socks Proxy Type')),
                ('socks_proxy_host', models.GenericIPAddressField(blank=True, help_text='Socks proxy IP address. Default: 127.0.0.1', null=True, verbose_name='Socks Proxy Host')),
                ('socks_proxy_port', models.IntegerField(blank=True, help_text='Socks proxy port number. Default: 9150 (default TOR port)', null=True, verbose_name='Socks Proxy Port')),
                ('logging_type', models.CharField(blank=True, choices=[('none', 'None'), ('debug', 'Debug'), ('info', 'Information'), ('warn', 'Warning'), ('error', 'Error'), ('crit', 'Critical')], help_text='Set the default logging level. All messages at that level or above will be logged to the directory set below. If no level is set, logging will be disabled.', max_length=5, null=True, verbose_name='Logging Type')),
                ('logging_dir', models.CharField(blank=True, help_text='If logging is enabled, what directory should we use to store log files for this queue? The standard logging mechanisms are used if no directory is set', max_length=200, null=True, verbose_name='Logging Directory')),
                ('dedicated_time', models.DurationField(blank=True, help_text='Time to be spent on this Queue in total', null=True)),
            ],
            options={
                'verbose_name': 'Queue',
                'verbose_name_plural': 'Queues',
                'ordering': ('title',),
            },
        ),
        migrations.CreateModel(
            name='SavedSearch',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(help_text='User-provided name for this query', max_length=100, verbose_name='Query Name')),
                ('shared', models.BooleanField(blank=True, default=False, help_text='Should other users see this query?', verbose_name='Shared With Other Users?')),
                ('query', models.TextField(help_text='Pickled query object. Be wary changing this.', verbose_name='Search Query')),
            ],
            options={
                'verbose_name': 'Saved search',
                'verbose_name_plural': 'Saved searches',
            },
        ),
        migrations.CreateModel(
            name='Ticket',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=200, verbose_name='Title')),
                ('created', models.DateTimeField(auto_now_add=True, help_text='Date this ticket was first created', verbose_name='Created')),
                ('modified', models.DateTimeField(auto_now=True, help_text='Date this ticket was most recently changed.', verbose_name='Modified')),
                ('submitter_email', models.EmailField(blank=True, help_text='The submitter will receive an email for all public follow-ups left for this task.', max_length=254, null=True, verbose_name='Submitter E-Mail')),
                ('status', models.IntegerField(choices=[(1, 'Open'), (2, 'Reopened'), (3, 'Resolved'), (4, 'Closed'), (5, 'Duplicate')], default=1, verbose_name='Status')),
                ('on_hold', models.BooleanField(blank=True, default=False, help_text='If a ticket is on hold, it will not automatically be escalated.', verbose_name='On Hold')),
                ('description', models.TextField(blank=True, help_text='The content of the customers query.', null=True, verbose_name='Description')),
                ('resolution', models.TextField(blank=True, help_text='The resolution provided to the customer by our staff.', null=True, verbose_name='Resolution')),
                ('priority', models.IntegerField(blank=3, choices=[(1, '1. Critical'), (2, '2. High'), (3, '3. Normal'), (4, '4. Low'), (5, '5. Very Low')], default=3, help_text='1 = Highest Priority, 5 = Low Priority', verbose_name='Priority')),
                ('due_date', models.DateTimeField(blank=True, null=True, verbose_name='Due on')),
                ('last_escalation', models.DateTimeField(blank=True, editable=False, help_text='The date this ticket was last escalated - updated automatically by management/commands/escalate_tickets.py.', null=True)),
                ('secret_key', models.CharField(default=helpdesk.models.mk_secret, max_length=36, verbose_name='Secret key needed for viewing/editing ticket by non-logged in users')),
            ],
            options={
                'verbose_name': 'Ticket',
                'verbose_name_plural': 'Tickets',
                'ordering': ('id',),
                'get_latest_by': 'created',
            },
        ),
        migrations.CreateModel(
            name='TicketCC',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email', models.EmailField(blank=True, help_text='For non-user followers, enter their e-mail address', max_length=254, null=True, verbose_name='E-Mail Address')),
                ('can_view', models.BooleanField(blank=True, default=False, help_text='Can this CC login to view the ticket details?', verbose_name='Can View Ticket?')),
                ('can_update', models.BooleanField(blank=True, default=False, help_text='Can this CC login and update the ticket?', verbose_name='Can Update Ticket?')),
            ],
        ),
        migrations.CreateModel(
            name='TicketChange',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('field', models.CharField(max_length=200, verbose_name='Field')),
                ('old_value', models.TextField(blank=True, null=True, verbose_name='Old Value')),
                ('new_value', models.TextField(blank=True, null=True, verbose_name='New Value')),
            ],
            options={
                'verbose_name': 'Ticket change',
                'verbose_name_plural': 'Ticket changes',
            },
        ),
        migrations.CreateModel(
            name='TicketCustomFieldValue',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('value', models.TextField(blank=True, null=True)),
            ],
            options={
                'verbose_name': 'Ticket custom field value',
                'verbose_name_plural': 'Ticket custom field values',
            },
        ),
        migrations.CreateModel(
            name='TicketDependency',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
            ],
            options={
                'verbose_name': 'Ticket dependency',
                'verbose_name_plural': 'Ticket dependencies',
            },
        ),
        migrations.CreateModel(
            name='UserSettings',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('settings_pickled', models.TextField(blank=True, help_text='DEPRECATED! This is a base64-encoded representation of a pickled Python dictionary. Do not change this field via the admin.', null=True, verbose_name='DEPRECATED! Settings Dictionary DEPRECATED!')),
                ('login_view_ticketlist', models.BooleanField(default=helpdesk.models.login_view_ticketlist_default, help_text='Display the ticket list upon login? Otherwise, the dashboard is shown.', verbose_name='Show Ticket List on Login?')),
                ('email_on_ticket_change', models.BooleanField(default=helpdesk.models.email_on_ticket_change_default, help_text="If you're the ticket owner and the ticket is changed via the web by somebody else,do you want to receive an e-mail?", verbose_name='E-mail me on ticket change?')),
                ('email_on_ticket_assign', models.BooleanField(default=helpdesk.models.email_on_ticket_assign_default, help_text='If you are assigned a ticket via the web, do you want to receive an e-mail?', verbose_name='E-mail me when assigned a ticket?')),
                ('tickets_per_page', models.IntegerField(choices=[(10, '10'), (25, '25'), (50, '50'), (100, '100')], default=helpdesk.models.tickets_per_page_default, help_text='How many tickets do you want to see on the Ticket List page?', verbose_name='Number of tickets to show per page')),
                ('use_email_as_submitter', models.BooleanField(default=helpdesk.models.use_email_as_submitter_default, help_text='When you submit a ticket, do you want to automatically use your e-mail address as the submitter address? You can type a different e-mail address when entering the ticket if needed, this option only changes the default.', verbose_name='Use my e-mail address when submitting tickets?')),
            ],
            options={
                'verbose_name': 'User Setting',
                'verbose_name_plural': 'User Settings',
            },
        ),
        migrations.CreateModel(
            name='ChecklistTask',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('description', models.CharField(max_length=250, verbose_name='Description')),
                ('completion_date', models.DateTimeField(blank=True, null=True, verbose_name='Completion Date')),
                ('position', models.PositiveSmallIntegerField(db_index=True, verbose_name='Position')),
                ('checklist', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='tasks', to='helpdesk.checklist', verbose_name='Checklist')),
            ],
            options={
                'verbose_name': 'Checklist Task',
                'verbose_name_plural': 'Checklist Tasks',
                'ordering': ('position',),
            },
        ),
    ]
