import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('helpdesk', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='followup',
            name='user',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL, verbose_name='User'),
        ),
        migrations.AddField(
            model_name='followupattachment',
            name='followup',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='helpdesk.followup', verbose_name='Follow-up'),
        ),
        migrations.AddField(
            model_name='kbitem',
            name='category',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='helpdesk.kbcategory', verbose_name='Category'),
        ),
        migrations.AddField(
            model_name='kbitem',
            name='downvoted_by',
            field=models.ManyToManyField(related_name='downvotes', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='kbitem',
            name='team',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL, verbose_name='Team'),
        ),
        migrations.AddField(
            model_name='kbitem',
            name='voted_by',
            field=models.ManyToManyField(related_name='votes', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='kbiattachment',
            name='kbitem',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='helpdesk.kbitem', verbose_name='Knowledge base item'),
        ),
        migrations.AddField(
            model_name='queue',
            name='default_owner',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='default_owner', to=settings.AUTH_USER_MODEL, verbose_name='Default owner'),
        ),
        migrations.AddField(
            model_name='presetreply',
            name='queues',
            field=models.ManyToManyField(blank=True, help_text='Leave blank to allow this reply to be used for all queues, or select those queues you wish to limit this reply to.', to='helpdesk.queue'),
        ),
        migrations.AddField(
            model_name='kbcategory',
            name='queue',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='helpdesk.queue', verbose_name='Default queue when creating a ticket after viewing this category.'),
        ),
        migrations.AddField(
            model_name='ignoreemail',
            name='queues',
            field=models.ManyToManyField(blank=True, help_text='Leave blank for this e-mail to be ignored on all queues, or select those queues you wish to ignore this e-mail for.', to='helpdesk.queue'),
        ),
        migrations.AddField(
            model_name='escalationexclusion',
            name='queues',
            field=models.ManyToManyField(blank=True, help_text='Leave blank for this exclusion to be applied to all queues, or select those queues you wish to exclude with this entry.', to='helpdesk.queue'),
        ),
        migrations.AddField(
            model_name='savedsearch',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL, verbose_name='User'),
        ),
        migrations.AddField(
            model_name='ticket',
            name='assigned_to',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='assigned_to', to=settings.AUTH_USER_MODEL, verbose_name='Assigned to'),
        ),
        migrations.AddField(
            model_name='ticket',
            name='kbitem',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='helpdesk.kbitem', verbose_name='Knowledge base item the user was viewing when they created this ticket.'),
        ),
        migrations.AddField(
            model_name='ticket',
            name='merged_to',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='merged_tickets', to='helpdesk.ticket', verbose_name='merged to'),
        ),
        migrations.AddField(
            model_name='ticket',
            name='queue',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='helpdesk.queue', verbose_name='Queue'),
        ),
        migrations.AddField(
            model_name='followup',
            name='ticket',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='helpdesk.ticket', verbose_name='Ticket'),
        ),
        migrations.AddField(
            model_name='checklist',
            name='ticket',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='checklists', to='helpdesk.ticket', verbose_name='Ticket'),
        ),
        migrations.AddField(
            model_name='ticketcc',
            name='ticket',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='helpdesk.ticket', verbose_name='Ticket'),
        ),
        migrations.AddField(
            model_name='ticketcc',
            name='user',
            field=models.ForeignKey(blank=True, help_text='User who wishes to receive updates for this ticket.', null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL, verbose_name='User'),
        ),
        migrations.AddField(
            model_name='ticketchange',
            name='followup',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='helpdesk.followup', verbose_name='Follow-up'),
        ),
        migrations.AddField(
            model_name='ticketcustomfieldvalue',
            name='field',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='helpdesk.customfield', verbose_name='Field'),
        ),
        migrations.AddField(
            model_name='ticketcustomfieldvalue',
            name='ticket',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='helpdesk.ticket', verbose_name='Ticket'),
        ),
        migrations.AddField(
            model_name='ticketdependency',
            name='depends_on',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='depends_on', to='helpdesk.ticket', verbose_name='Depends On Ticket'),
        ),
        migrations.AddField(
            model_name='ticketdependency',
            name='ticket',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='ticketdependency', to='helpdesk.ticket', verbose_name='Ticket'),
        ),
        migrations.AddField(
            model_name='usersettings',
            name='user',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='usersettings_helpdesk', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterUniqueTogether(
            name='ticketcustomfieldvalue',
            unique_together={('ticket', 'field')},
        ),
        migrations.AlterUniqueTogether(
            name='ticketdependency',
            unique_together={('ticket', 'depends_on')},
        ),
    ]
