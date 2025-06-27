from flask import Blueprint, render_template, request, redirect, url_for
from auth import admin_required
from db import create_policy as write_create_policy, get_policies as read_get_policies, edit_policy as write_edit_policy, get_policy as read_get_policy, delete_policy as write_delete_policy, create_assignment as write_create_assignment, get_pending_assignments as read_get_pending_assignments, delete_assignment as write_delete_assignment, get_users as read_get_users

admin = Blueprint('admin', __name__, url_prefix='/admin')

@admin.route('/choice', methods=['GET'])
@admin_required
def choice():
    return render_template('admin/choice.html')

@admin.route('/dashboard', methods=['GET'])
@admin_required
def dashboard():
    return render_template('admin/dashboard.html')

@admin.route('/manage_policies', methods=['GET'])
@admin_required
def manage_policies():
    policies = read_get_policies()
    return render_template('admin/manage_policies/hub.html', policies=policies["data"])

@admin.route('/manage_policies/create', methods=['GET', 'POST'])
@admin_required
def create_policy():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        pdf_link = request.form['pdf_link']
        write_create_policy(name, description, pdf_link)
        return redirect(url_for('admin.manage_policies'))
    return render_template('admin/manage_policies/create.html')

@admin.route('/manage_policies/edit', methods=['GET', 'POST'])
@admin_required
def edit_policy():
    if request.method == 'POST':
        policy_uuid = request.form['policy']
        original_policy = read_get_policy(uuid=policy_uuid)["data"]
        name = request.form['name'] if request.form['name'] else original_policy["name"]
        description = request.form['description'] if request.form['description'] else original_policy["description"]
        pdf_link = request.form['pdf_link'] if request.form['pdf_link'] else original_policy["pdf_link"]
        write_edit_policy(policy_uuid, name, description, pdf_link)
        return redirect(url_for('admin.manage_policies'))
    policies = read_get_policies()
    return render_template('admin/manage_policies/edit.html', policies=policies["data"])
    
@admin.route('/manage_policies/delete', methods=['GET', 'POST'])
@admin_required
def delete_policy():
    if request.method == 'POST':
        policy_uuid = request.form['policy']
        write_delete_policy(policy_uuid)
        return redirect(url_for('admin.manage_policies'))
    policies = read_get_policies()
    return render_template('admin/manage_policies/delete.html', policies=policies["data"])

@admin.route('/manage_assignments', methods=['GET'])
@admin_required
def manage_assignments():
    assignments = read_get_pending_assignments()
    return render_template('admin/manage_assignments/hub.html', assignments=assignments["data"])

@admin.route('/manage_assignments/delete', methods=['GET', 'POST'])
@admin_required
def delete_assignment():
    if request.method == 'POST':
        assignment_uuid = request.form['assignment']
        write_delete_assignment(assignment_uuid)
        return redirect(url_for('admin.manage_assignments'))
    assignments = read_get_pending_assignments()
    return render_template('admin/manage_assignments/delete.html', assignments=assignments["data"])

@admin.route('/manage_assignments/create', methods=['GET', 'POST'])
@admin_required
def create_assignment():
    if request.method == 'POST':
        user_uuid = request.form['user']
        policy_uuid = request.form['policy']
        timeframe_days = int(request.form['timeframe_days'])
        write_create_assignment(user_uuid, policy_uuid, timeframe_days)
        return redirect(url_for('admin.manage_assignments'))
    users = read_get_users()
    policies = read_get_policies()
    return render_template('admin/manage_assignments/create.html', users=users["data"], policies=policies["data"])
