# Generated by Django 5.1.1 on 2024-10-29 15:42

import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myApp', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='MedicalAccessories',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('p_image', models.ImageField(upload_to='')),
                ('p_name', models.CharField(max_length=100)),
                ('p_description', models.CharField(max_length=1000)),
                ('p_category', models.CharField(choices=[('Medicine', 'Medicine'), ('Equipment', 'Equipment')], max_length=10)),
                ('p_cost', models.IntegerField()),
                ('p_count', models.IntegerField()),
                ('v_name', models.CharField(max_length=100)),
                ('v_description', models.CharField(max_length=100)),
            ],
        ),
        migrations.CreateModel(
            name='Bill',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('total_cost', models.DecimalField(decimal_places=2, max_digits=10)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('customer', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='CartItem',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('quantity', models.IntegerField(default=1)),
                ('total_cost', models.IntegerField(null=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ('accessory', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='myApp.medicalaccessories')),
            ],
        ),
        migrations.CreateModel(
            name='BillItem',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('quantity', models.IntegerField()),
                ('total_cost', models.DecimalField(decimal_places=2, max_digits=10)),
                ('bill', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='myApp.bill')),
                ('accessory', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='myApp.medicalaccessories')),
            ],
        ),
        migrations.AddField(
            model_name='bill',
            name='accessories',
            field=models.ManyToManyField(through='myApp.BillItem', to='myApp.medicalaccessories'),
        ),
    ]