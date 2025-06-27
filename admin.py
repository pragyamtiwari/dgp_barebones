from flask import Blueprint, render_template, request, redirect, url_for, flash
from auth import admin_required
from db import (
    create_policy as write_create_policy, 
    get_policies as read_get_policies, 
    edit_policy as write_edit_policy, 
    get_policy as read_get_policy, 
    delete_policy as write_delete_policy, 
    create_assignment as write_create_assignment, 
    get_pending_assignments as read_get_pending_assignments, 
    delete_assignment as write_delete_assignment, 
    get_users as read_get_users, 
    promote_user_to_admin as write_promote_user_to_admin, 
    demote_user_from_admin as write_demote_user_from_admin,
    get_user,  # Added this import
    get_assignments_by_policy  # Add this import
)

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
        # Get selected policies (can be multiple)
        selected_policies = request.form.getlist('policies')
        
        # Track results
        successful_deletions = 0
        failed_deletions = []
        total_assignments_deleted = 0
        
        # Delete each selected policy
        for policy_uuid in selected_policies:
            # First, count assignments that will be deleted
            assignments_result = get_assignments_by_policy(policy_uuid)
            if assignments_result['status'] == '200':
                total_assignments_deleted += len(assignments_result['data'])
            
            # Delete the policy (which will cascade delete assignments)
            result = write_delete_policy(policy_uuid)
            if result['status'] == '200':
                successful_deletions += 1
            else:
                # Get policy info for error reporting
                policy_info = read_get_policy(uuid=policy_uuid)
                policy_name = policy_info['data']['name'] if policy_info['status'] == '200' else 'Unknown Policy'
                failed_deletions.append({
                    'policy_name': policy_name,
                    'error': result['message']
                })
        
        # Flash success/error messages
        if successful_deletions > 0:
            message = f'Successfully deleted {successful_deletions} polic{"ies" if successful_deletions != 1 else "y"}'
            if total_assignments_deleted > 0:
                message += f' and {total_assignments_deleted} associated assignment{"s" if total_assignments_deleted != 1 else ""}'
            message += '!'
            flash(message, 'success')
        
        if failed_deletions:
            for failure in failed_deletions:
                flash(f'Failed to delete policy "{failure["policy_name"]}": {failure["error"]}', 'error')
        
        return redirect(url_for('admin.manage_policies'))
    
    # GET request - show the form with policies and assignment counts
    policies_result = read_get_policies()
    if policies_result['status'] == '200':
        # Convert Row objects to dictionaries so we can modify them
        policies = [dict(policy) for policy in policies_result['data']]
        
        # Add assignment count to each policy
        for policy in policies:
            assignments_result = get_assignments_by_policy(policy['uuid'])
            if assignments_result['status'] == '200':
                policy['assignment_count'] = len(assignments_result['data'])
            else:
                policy['assignment_count'] = 0
    else:
        policies = []
    
    return render_template('admin/manage_policies/delete.html', policies=policies)
from time import time

@admin.route('/manage_assignments', methods=['GET'])
@admin_required
def manage_assignments():
    assignments = read_get_pending_assignments()
    return render_template('admin/manage_assignments/hub.html', 
                         assignments=assignments["data"],
                         now=int(time()))

@admin.route('/manage_assignments/delete', methods=['GET', 'POST'])
@admin_required
def delete_assignment():
    if request.method == 'POST':
        # Get selected assignments (can be multiple)
        selected_assignments = request.form.getlist('assignments')
        
        # Track results
        successful_deletions = 0
        failed_deletions = []
        
        # Delete each selected assignment
        for assignment_uuid in selected_assignments:
            result = write_delete_assignment(assignment_uuid)
            if result['status'] == '200':
                successful_deletions += 1
            else:
                failed_deletions.append({
                    'assignment_uuid': assignment_uuid,
                    'error': result['message']
                })
        
        # Flash success/error messages
        if successful_deletions > 0:
            flash(f'Successfully deleted {successful_deletions} assignment{"s" if successful_deletions != 1 else ""}!', 'success')
        
        if failed_deletions:
            for failure in failed_deletions:
                flash(f'Failed to delete assignment: {failure["error"]}', 'error')
        
        return redirect(url_for('admin.manage_assignments'))
    
    # GET request - show the form
    assignments = read_get_pending_assignments()
    return render_template('admin/manage_assignments/delete.html', assignments=assignments["data"])

@admin.route('/manage_assignments/create', methods=['GET', 'POST'])
@admin_required
def create_assignment():
    if request.method == 'POST':
        # Get selected users (can be multiple)
        selected_users = request.form.getlist('users')
        policy_uuid = request.form['policy']
        timeframe_days = int(request.form['timeframe_days'])
        
        # Track results
        successful_assignments = 0
        failed_assignments = []
        
        # Create assignment for each selected user
        for user_uuid in selected_users:
            result = write_create_assignment(user_uuid, policy_uuid, timeframe_days)
            if result['status'] == '201':
                successful_assignments += 1
            else:
                # Get user info for error reporting
                user_info = get_user(uuid=user_uuid)
                user_name = user_info['data']['name'] if user_info['status'] == '200' else 'Unknown User'
                failed_assignments.append({
                    'user_name': user_name,
                    'error': result['message']
                })
        
        # Flash success/error messages
        if successful_assignments > 0:
            flash(f'Successfully created {successful_assignments} assignment{"s" if successful_assignments != 1 else ""}!', 'success')
        
        if failed_assignments:
            for failure in failed_assignments:
                flash(f'Failed to create assignment for {failure["user_name"]}: {failure["error"]}', 'error')
        
        return redirect(url_for('admin.manage_assignments'))
    
    # GET request - show the form
    users = read_get_users()
    policies = read_get_policies()
    return render_template('admin/manage_assignments/create.html', 
                         users=users["data"], 
                         policies=policies["data"])

@admin.route('/manage_users', methods=['GET'])
@admin_required
def manage_users():
    return render_template('admin/manage_users/hub.html')

@admin.route('/manage_users/promote', methods=['GET', 'POST'])
@admin_required
def promote_user():
    if request.method == 'POST':
        # Get selected users (can be multiple)
        selected_users = request.form.getlist('users')
        
        # Track results
        successful_promotions = 0
        failed_promotions = []
        
        # Promote each selected user
        for user_uuid in selected_users:
            result = write_promote_user_to_admin(user_uuid)
            if result['status'] == '200':
                successful_promotions += 1
            else:
                # Get user info for error reporting
                user_info = get_user(uuid=user_uuid)
                user_name = user_info['data']['name'] if user_info['status'] == '200' else 'Unknown User'
                failed_promotions.append({
                    'user_name': user_name,
                    'error': result['message']
                })
        
        # Flash success/error messages
        if successful_promotions > 0:
            flash(f'Successfully promoted {successful_promotions} user{"s" if successful_promotions != 1 else ""} to administrator!', 'success')
        
        if failed_promotions:
            for failure in failed_promotions:
                flash(f'Failed to promote {failure["user_name"]}: {failure["error"]}', 'error')
        
        return redirect(url_for('admin.manage_users'))
    
    # GET request - show only non-admin users
    users = read_get_users()["data"]
    users = [user for user in users if not user['is_admin']]
    return render_template('admin/manage_users/promote.html', users=users)

@admin.route('/manage_users/demote', methods=['GET', 'POST'])
@admin_required
def demote_user():
    if request.method == 'POST':
        # Get selected users (can be multiple)
        selected_users = request.form.getlist('users')
        
        # Get current admin count
        all_users = read_get_users()["data"]
        admin_count = sum(1 for user in all_users if user['is_admin'])
        
        # Ensure we don't demote all admins
        if len(selected_users) >= admin_count:
            flash('Cannot demote all administrators. At least one must remain.', 'error')
            return redirect(url_for('admin.manage_users'))
        
        # Track results
        successful_demotions = 0
        failed_demotions = []
        
        # Demote each selected user
        for user_uuid in selected_users:
            result = write_demote_user_from_admin(user_uuid)
            if result['status'] == '200':
                successful_demotions += 1
            else:
                # Get user info for error reporting
                user_info = get_user(uuid=user_uuid)
                user_name = user_info['data']['name'] if user_info['status'] == '200' else 'Unknown User'
                failed_demotions.append({
                    'user_name': user_name,
                    'error': result['message']
                })
        
        # Flash success/error messages
        if successful_demotions > 0:
            flash(f'Successfully demoted {successful_demotions} administrator{"s" if successful_demotions != 1 else ""} to regular user!', 'success')
        
        if failed_demotions:
            for failure in failed_demotions:
                flash(f'Failed to demote {failure["user_name"]}: {failure["error"]}', 'error')
        
        return redirect(url_for('admin.manage_users'))
    
    # GET request - show only admin users
    users = read_get_users()["data"]
    users = [user for user in users if user['is_admin']]
    return render_template('admin/manage_users/demote.html', users=users)